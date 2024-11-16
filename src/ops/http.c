#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <uv/tree.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/base64.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <llhttp.h>
#include <common/sds.h>
#include "http.h"
#include "ops/module/dst.h"
#include "bridge.h"



#if (defined(_WIN32) || defined(_WIN64))
#define strcasecmp stricmp
#define strncasecmp  strnicmp
#endif

//HTTP请求头
typedef struct _ops_http_header {
    sds key;
    sds value;
    struct _ops_http_header* next;
}ops_http_header;
//HTTP请求
typedef struct _ops_http_request {
    RB_ENTRY(_ops_http_request) entry;          //
    uint32_t id;                                //请求ID
    struct _ops_http_stream* stream;            //关联的流

    llhttp_method_t method;                     //请求方式
    sds host;                                   //主机
    sds url;                                    //请求地址
    sds body;                                   //请求数据
    ops_http_header* header;                    //请求头
    ops_http_header* cur_header;                //

    struct _ops_host* service;
}ops_http_request;
RB_HEAD(_ops_http_request_tree, _ops_http_request);
//HTTP流
typedef struct _ops_http_stream {
    RB_ENTRY(_ops_http_stream) entry;           //
    uint32_t id;                                //流id
    struct _ops_http_conn* conn;                //流对应的连接
    union {
        struct {
            llhttp_t parser;                 //http解析器
            uint8_t parser_step;                //解析进度
        }h1;
        struct {
            uint16_t status_code;
            int32_t local_window_size;      //本地窗口
            int32_t remote_window_size;     //远端窗口
        }h2;
    } u;
    struct {
        uint8_t keepalive : 1;              //长链接
    } b;
    ops_http_request* request;                  //流对应的请求
}ops_http_stream;
RB_HEAD(_ops_http_stream_tree, _ops_http_stream);
//HTTP连接
typedef struct _ops_http_conn {
    ops_http* http;
    uv_tcp_t tcp;               //连接

    uint8_t http_major;                 //协议版本,主
    uint8_t http_minor;                 //协议版本,次

    uint32_t sid;                           //当前分配到的ID
    struct _ops_http_stream_tree stream;    //流
    struct {
        SSL* ssl;
        BIO* rio;
        BIO* wio;
    }ssl;
    struct {
        uint8_t ssl : 1;                //TLS协议
    } b;
}ops_http_conn;
//域名服务
typedef struct _ops_host {
    RB_ENTRY(_ops_host) entry;          //
    const char* host;                   //主机
    const char* host_rewrite;           //重写主机
    uint32_t id;                        //服务ID
    uint16_t dst_id;                    //目标客户ID
    uint32_t dst;                       //目标ID
    struct {
        uint8_t x_real_ip : 1;          //转发真实IP
        uint8_t x_forwarded_for : 1;    //转发真实IP
    }b;
}ops_host;
RB_HEAD(_ops_host_tree, _ops_host);
typedef struct _ops_http {
    ops_global* global;
    ops_bridge_manager* manager;            //客户端管理器
    struct _ops_host_tree host;             //域名

    uint32_t request_id;                    //HTTP请求ID
    struct _ops_http_request_tree request;  //HTTP请求

    uv_tcp_t http;                      //
    struct {
        SSL_CTX* ctx;
        uv_tcp_t tcp;                     //
    }https;
}ops_http;


static int _ops_host_compare(ops_host* w1, ops_host* w2) {
    return strcasecmp(w1->host, w2->host);
}
RB_GENERATE_STATIC(_ops_host_tree, _ops_host, entry, _ops_host_compare)
static int _ops_http_request_compare(ops_http_request* w1, ops_http_request* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_http_request_tree, _ops_http_request, entry, _ops_http_request_compare)
static int _ops_http_stream_compare(ops_http_stream* w1, ops_http_stream* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_http_stream_tree, _ops_http_stream, entry, _ops_http_stream_compare)

static void http_close_cb(uv_handle_t* handle);
//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
//发送回调
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
//清理请求
static void http_request_clean(ops_http_request* req) {
    if (req->body) {
        sdsfree(req->body);
        req->body = NULL;
    }
    if (req->url) {
        sdsfree(req->url);
        req->url = NULL;
    }
    if (req->host) {
        sdsfree(req->host);
        req->host = NULL;
    }
    req->service = NULL;

    ops_http_header* header = req->header;
    ops_http_header* next;
    while (header) {
        if (header->key)
            sdsfree(header->key);
        if (header->value)
            sdsfree(header->value);
        next = header->next;
        free(header);
        header = next;
    }
    req->header = NULL;

}
//查找请求头
static ops_http_header* http_request_find_header(ops_http_request* req, const char* key) {
    ops_http_header* header = req->header;
    while (header) {
        if (strcasecmp(header->key, key) == 0) {
            return header;
        }
        header = header->next;
    }
    return NULL;
}
//
static int http_send(ops_http_conn* conn, char* data, uint32_t size) {
    //转发数据到远程
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(size);
    if (buf->base == NULL) {
        return -1;
    }
    memcpy(buf->base, data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return -1;
    }
    req->data = buf->base;
    return uv_write(req, &conn->tcp, &buf, 1, write_cb);
}
//发送html应答
static void http_respose_html(ops_http_conn* conn, const char* html, int len) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: text/html;charset=utf-8;\r\n"
        "\r\n",
        200, "OK", len);
    //数据
    data = sdscatlen(data, html, len);
    http_send(conn, data, sdslen(data));
    sdsfree(data);
}
//HTTP应答解析回调
//消息完毕
static int http_on_message_complete(llhttp_t* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;

    if (!req->host) {
        http_request_clean(req);
        http_respose_html(s->conn, "Host Not Found", 13);
        return 0;
    }

    //日志
    printf("New Request %s %s\r\n", req->host, req->url);

    //查找域名转发
    ops_host the = {
        .host = req->host
    };
    ops_host* host = RB_FIND(_ops_host_tree, &s->conn->http->host, &the);
    if (host == NULL) {
        http_request_clean(req);
        http_respose_html(s->conn, "Client Not Found", 13);
        return 0;
    }
    //查找目标客户端是否在线
    ops_bridge* b = bridge_find(s->conn->http->manager, host->dst_id);
    if (b == NULL) {
        http_request_clean(req);
        http_respose_html(s->conn, "Client Offline", 13);
        return 0;
    }
    //给请求关联对应的服务
    req->service = host;
    //打开目标
    uint8_t buf[1];
    buf[0] = CTL_DST_CTL_OPEN;
    bridge_send_mod(b, MODULE_DST, dst_packet_ctl, host->dst, req->id, buf, sizeof(buf));
    return 0;
}
//解析到消息体
static int http_on_body(llhttp_t* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (!req->body) {
        req->body = sdsnewlen(buf, len);
    }
    else {
        req->body = sdscatlen(req->body, buf, len);
    }
    return 0;
}
//解析到头V
static int http_on_header_value(llhttp_t* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (req->cur_header->value == NULL)
        req->cur_header->value = sdsempty();
    req->cur_header->value = sdscatlen(req->cur_header->value, buf, len);
    return 0;
}
//解析到头K
static int http_on_header_field(llhttp_t* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (req->header == NULL) {
        req->header = malloc(sizeof(ops_http_header));
        memset(req->header, 0, sizeof(ops_http_header));
        req->cur_header = req->header;
    }
    //上一个kv解析完毕
    if (req->cur_header->value != NULL) {
        //
        if (strcasecmp(req->cur_header->key, "host") == 0) {
            req->host = sdsdup(req->cur_header->value);
        }
        //分配新的kv
        req->cur_header->next = malloc(sizeof(ops_http_header));
        memset(req->cur_header->next, 0, sizeof(ops_http_header));
        req->cur_header = req->cur_header->next;
    }
    //
    if (req->cur_header->key == NULL)
        req->cur_header->key = sdsempty();
    req->cur_header->key = sdscatlen(req->cur_header->key, buf, len);
    return 0;
}
//头部解析完毕
static int http_on_headers_complete(llhttp_t* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    req->cur_header = NULL;
    return 0;
}
//
static int http_on_url(llhttp_t* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (req->url == NULL) {
        req->url = sdsnewlen(buf, len);
    }
    else {
        req->url = sdscatlen(req->url, buf, len);
    }
    return 0;
}
//解析开始
static int http_on_message_begin(llhttp_t* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    req->method = p->method;
    return 0;
}
//重置请求
static int http_on_reset(llhttp_t* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    http_request_clean(req);
    return 0;
}
//解析器设置
static llhttp_settings_t  parser_settings = {
    http_on_message_begin,
    http_on_url,
    NULL,
    NULL,
    NULL,
    http_on_header_field,
    http_on_header_value,
    NULL,
    NULL,
    http_on_headers_complete,
    http_on_body,
    http_on_message_complete,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_on_reset
};
//创建流
static ops_http_stream* http_conn_stream_create(ops_http_conn* conn) {
    if (!conn)
        return NULL;
    uint32_t id = 0;
    //HTTP2
    if (conn->http_major == 2) {
        conn->sid += 2;
        id = conn->sid;
    }
    else {
        //http1只支持1个流
        if (conn->sid == 0) {
            conn->sid++;
            id = conn->sid;
        }
        else {
            return NULL;
        }
    }
    //创建流对象
    ops_http_stream* s = malloc(sizeof(*s));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));
    s->id = id;
    s->conn = conn;
    if (conn->http_major == 2) {
        //
    }
    else {
        //准备解析器
        llhttp_init(&s->u.h1.parser, HTTP_REQUEST, &parser_settings);
        s->u.h1.parser.data = s;
    }
    //创建请求
    ops_http_request* req = (ops_http_request*)malloc(sizeof(*req));
    if (req == NULL) {
        free(s);
        return NULL;
    }
    memset(req, 0, sizeof(*req));
    req->id = conn->http->request_id++;
    req->stream = s;
    RB_INSERT(_ops_http_request_tree, &conn->http->request, req);
    s->request = req;
    //记录流
    RB_INSERT(_ops_http_stream_tree, &conn->stream, s);
    return s;
}
//关闭流
void http_conn_stream_close(ops_http_conn* conn, int id) {
    if (!conn)
        return;
    //查找流
    ops_http_stream the = { 0 };
    the.id = id;
    ops_http_stream* s = RB_FIND(_ops_http_stream_tree, &conn->stream, &the);
    if (!s) {
        return;
    }
    //HTTP2
    if (conn->http_major == 2) {


    }
    else {
        //http1只支持1个流
        conn->sid = 0;
    }
    //释放请求


    RB_REMOVE(_ops_http_stream_tree, &conn->stream, s);
    free(s);
}
//处理http1帧数据
static int http_1_frame(ops_http_conn* conn, uint8_t* buf, size_t len) {
    //查找流
    ops_http_stream the = { 0 };
    the.id = 1;
    ops_http_stream* s = RB_FIND(_ops_http_stream_tree, &conn->stream, &the);
    if (!s) {
        s = http_conn_stream_create(conn);
        if (!s)
            return 1;
    }
    enum llhttp_errno err = llhttp_execute(&s->u.h1.parser, buf, len);
    if (err != HPE_OK) {
        //处理失败
        uv_close(&conn->tcp, http_close_cb);
    }
    return 1;
}
//处理接收数据
static int http_conn_data(ops_http_conn* conn, uint8_t* buf, size_t len) {
    if (conn->http_major == 2) {

    }
    else {
        return http_1_frame(conn, buf, len);
    }
    return 0;
}
//连接关闭
static void http_close_cb(uv_handle_t* handle) {
    ops_http_conn* conn = (ops_http_conn*)handle->data;
    
    free(conn);
}
static void http_shutdown_cb(uv_shutdown_t* req, int status) {
    ops_http_conn* conn = (ops_http_conn*)req->data;
    uv_close(&conn->tcp, http_close_cb);
    free(req);
}
//读取到数据
static void http_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_http_conn* conn = (ops_http_conn*)tcp->data;
    ops_http* http = conn->http;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, http_close_cb);
        }
        else {
            //shutdown
            uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
            if (req != NULL) {
                memset(req, 0, sizeof(*req));
                req->data = conn;
                uv_shutdown(req, tcp, http_shutdown_cb);
            }
            else {
                //分配内存失败,直接强制关闭
                uv_close(tcp, http_close_cb);
            }
        }
        return;
    }
    if (http_conn_data(conn, buf->base, nread)) {
        free(buf->base);
    }
}
//http连接进入
static void http_connection_cb(uv_stream_t* tcp, int status) {
    ops_http* http = (ops_http*)tcp->data;
    ops_http_conn* conn = (ops_http_conn*)malloc(sizeof(ops_http_conn));//为tcp bridge申请资源
    if (!conn)
        return;
    memset(conn, 0, sizeof(*conn));
    conn->http = http;

    uv_tcp_init(ops_get_loop(http->global), &conn->tcp);//初始化tcp bridge句柄
    conn->tcp.data = conn;

    if (uv_accept(tcp, (uv_stream_t*)&conn->tcp) == 0) {
        //默认协议版本是1.1
        conn->http_major = 1;
        conn->http_minor = 1;

        uv_read_start((uv_stream_t*)&conn->tcp, alloc_buffer, http_read_cb);
    }
}
//https连接进入
static void https_connection_cb(uv_stream_t* tcp, int status) {
    ops_http* http = (ops_http*)tcp->data;
    ops_http_conn* conn = (ops_http_conn*)malloc(sizeof(ops_http_conn));//为tcp bridge申请资源
    if (!conn)
        return;
    memset(conn, 0, sizeof(*conn));
    conn->http = http;

    uv_tcp_init(ops_get_loop(http->global), &conn->tcp);//初始化tcp句柄
    conn->tcp.data = conn;

    if (uv_accept(tcp, (uv_stream_t*)&conn->tcp) == 0) {
        //ssl协议
        conn->b.ssl = 1;
        //默认协议版本是1.1
        conn->http_major = 1;
        conn->http_minor = 1;

        uv_read_start((uv_stream_t*)&conn->tcp, alloc_buffer, http_read_cb);
    }
}
//----------------------------------------------------------------------------------------------------------------------
//创建主机模块
ops_http* http_new(ops_global* global, ops_bridge_manager* manager) {
    ops_http* http = (ops_http*)malloc(sizeof(*http));
    if (http == NULL) {
        return NULL;
    }
    memset(http, 0, sizeof(*http));
    RB_INIT(&http->host);
    http->global = global;
    http->manager = manager;

    struct sockaddr_in6 addr;
    //开始监听
    http->http.data = http;
    uv_tcp_init(ops_get_loop(global), &http->http);
    uv_ip6_addr("::0", opc_get_config(global)->http_proxy_port, &addr);
    uv_tcp_bind(&http->http, &addr, 0);
    uv_listen((uv_stream_t*)&http->http, 128, http_connection_cb);

    //https端口
    http->https.tcp.data = http;
    uv_tcp_init(ops_get_loop(global), &http->https.tcp);
    uv_ip6_addr("::0", opc_get_config(global)->https_proxy_port, &addr);
    uv_tcp_bind(&http->https.tcp, &addr, 0);
    uv_listen((uv_stream_t*)&http->https.tcp, 128, https_connection_cb);

    return http;
}
//控制数据
void http_host_ctl(ops_http* http, ops_bridge* bridge, uint32_t stream_id, uint8_t* data, int size) {
    ops_http_request the = {
        .id = stream_id
    };
    ops_http_request* req = RB_FIND(_ops_http_request_tree, &http->request, &the);
    if (req == NULL) {
        return;
    }
    //读取类型
    uint8_t type = data[0];
    switch (type)
    {
    case CTL_DST_CTL_SUC: {//连接远端成功
        //读取对端流ID
        uint32_t pree_id = ntohl(*(uint32_t*)(&data[1]));
        //生成新请求数据
        //生成数据
        sds d = sdscatprintf(sdsempty(),
            "%s %s HTTP/%d.%d\r\n",
            llhttp_method_name(req->method), req->url, 1, 1);
        //转发真实ip
        if (req->service->b.x_forwarded_for || req->service->b.x_real_ip) {
            //获取对端地址
            struct sockaddr_storage name;
            int namelen = sizeof(name);
            uv_tcp_getpeername(&req->stream->conn->tcp, &name, &namelen);
            //转换成字符串
            char addr[INET6_ADDRSTRLEN] = { 0 };
            uv_ip_name(&name, addr, sizeof(addr));
            if (req->service->b.x_real_ip) {
                //查找头部,存在则替换,不存在则添加
                ops_http_header* header = http_request_find_header(req, "x-real-ip");
                if (header == NULL) {
                    header = malloc(sizeof(ops_http_header));
                    if (header) {
                        header->key = sdsnew("x-real-ip");
                        header->value = sdsnew(addr);
                        header->next = req->header;
                        req->header = header;
                    }
                }
                else {
                    sdsfree(header->value);
                    header->value = sdsnew(addr);
                }
            }
            if (req->service->b.x_forwarded_for) {
                //查找头部,存在则追加,不存在则添加
                ops_http_header* header = http_request_find_header(req, "x-forwarded-for");
                if (header == NULL) {
                    header = malloc(sizeof(ops_http_header));
                    if (header) {
                        header->key = sdsnew("x-forwarded-for");
                        header->value = sdsnew(addr);
                        header->next = req->header;
                        req->header = header;
                    }
                }
                else {
                    sds v = sdscat(header->value, ", ");
                    v = sdscat(v, addr);
                    sdsfree(header->value);
                    header->value = v;
                }
            }
        }
        //头部
        ops_http_header* header = req->header;
        while (header) {
            d = sdscatsds(d, header->key);
            d = sdscat(d, ": ");
            //重写host
            if (strcasecmp(header->key, "host") == 0 && req->service->host_rewrite && req->service->host_rewrite[0] != 0) {
                d = sdscat(d, req->service->host_rewrite);
            }
            else {
                d = sdscatsds(d, header->value);
            }
            d = sdscat(d, "\r\n");
            header = header->next;
        }
        //请求结束
        d = sdscatprintf(d, "\r\n");
        //数据
        if (req->body) {
            d = sdscatsds(d, req->body);
        }
        //释放资源
        http_request_clean(req);

        //发送数据
        bridge_send_mod(bridge, MODULE_DST, dst_packet_data, 0, pree_id, d, sdslen(d));
        sdsfree(d);
        break;
    }
    case CTL_DST_CTL_ERR: {//连接远端失败

        break;
    }
    default:
        break;
    }
}
//转发客户端数据到远端
void http_host_data(ops_http* http, uint32_t stream_id, uint8_t* data, int size) {
    ops_http_request the = {
        .id = stream_id
    };
    ops_http_request* req = RB_FIND(_ops_http_request_tree, &http->request, &the);
    if (req == NULL) {
        return;
    }
    http_send(req->stream->conn, data, size);
}
//事件
void http_host_add(ops_http* http, uint32_t id, const char* src_host, uint16_t dst_id, uint8_t type, 
    const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite,
    uint8_t x_real_ip, uint8_t x_forwarded_for) {
    ops_host* host = malloc(sizeof(*host));
    if (host == NULL)
        return;
    memset(host, 0, sizeof(*host));
    //添加目标服务
    ops_dst_ctrl ctrl;
    ctrl.type = ops_dst_ctrl_add;
    ctrl.add.src_type = ops_src_type_host;
    ctrl.add.dst_id = dst_id;
    ctrl.add.type = type;
    ctrl.add.bind = bind;
    ctrl.add.dst = dst;
    ctrl.add.dst_port = dst_port;
    int dsts_id = bridge_mod_ctrl(http->manager, MODULE_DST, &ctrl);
    if (!dst_id) {
        free(host);
        return;
    }
    host->id = id;
    host->host = strdup(src_host);
    host->dst_id = dst_id;
    host->dst = dsts_id;
    host->b.x_real_ip = x_real_ip;
    host->b.x_forwarded_for = x_forwarded_for;
    if (host_rewrite) {
        host->host_rewrite = strdup(host_rewrite);
    }
    RB_INSERT(_ops_host_tree, &http->host, host);
    //下发
    /*
    ops_bridge* bridge = bridge_find(global, dst_id);
    if (!bridge) {
        return;
    }
    char buf[1 + 4 + sizeof(ops_dst)];
    buf[0] = CTL_DST_ADD;
    *(uint32_t*)(&buf[1]) = htonl(1);
    ops_dst _dst;
    _dst.port = htons(dst_port);
    _dst.sid = htonl(id);
    _dst.type = type;
    memcpy(_dst.dst, dst, sizeof(_dst.dst));
    memcpy(&buf[5], &_dst, sizeof(_dst));
    bridge_send(bridge, ops_packet_host, 0, 0, buf, sizeof(buf));
    */
}
void http_host_del(ops_http* http, const char* h) {
    ops_host _host = {
           .host = h
    };
    ops_host* host = RB_FIND(_ops_host_tree, &http->host, &_host);
    if (host == NULL) {
        return;
    }
    free(host->host);
    if (host->host_rewrite) {
        free(host->host_rewrite);
    }
    //通知相关客户端当前服务已移除

    RB_REMOVE(_ops_host_tree, &http->host, host);
    free(host);
}


