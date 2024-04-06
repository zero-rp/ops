#include <uv.h>
#include <cJSON.h>
#include <http_parser.h>
#include <uv/tree.h>
#include "databuffer.h"
#include "common.h"
#include "data.h"
#include "sds.h"

#if (defined(_WIN32) || defined(_WIN64))
#define strcasecmp stricmp
#define strncasecmp  strnicmp
#endif

#define DEFAULT_BACKLOG 128
//域名服务
typedef struct _ops_host {
    RB_ENTRY(_ops_forward) entry;       //
    const char* host;                   //主机
    const char* host_rewrite;           //重写主机
    uint32_t id;                        //服务ID
    uint16_t dst_id;                    //目标客户ID
    ops_host_dst dst;                   //目标信息
}ops_host;
RB_HEAD(_ops_host_tree, _ops_host);
//转发服务
typedef struct _ops_forward {
    RB_ENTRY(_ops_forward) entry;       //
    uint32_t id;                        //转发服务ID
    uint16_t src_id;                    //来源客户ID
    uint16_t dst_id;                    //目标客户ID
    ops_forward_dst dst;                //目标信息
    ops_forward_src src;                //来源信息
}ops_forward;
RB_HEAD(_ops_forward_tree, _ops_forward);
//客户端
typedef struct _ops_bridge {
    RB_ENTRY(_ops_bridge) entry;        //
    uint16_t id;                        //客户端ID
    struct _ops_global* global;
    uv_tcp_t tcp;                       //连接
    struct databuffer m_buffer;         //接收缓冲
}ops_bridge;
RB_HEAD(_ops_bridge_tree, _ops_bridge);
//授权信息
typedef struct _ops_auth {
    RB_ENTRY(_ops_auth) entry;          //
    const char* key;                    //
    uint16_t id;                        //客户端ID
}ops_auth;
RB_HEAD(_ops_auth_tree, _ops_auth);
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

    uint32_t method;                            //请求方式
    sds host;                   //主机
    sds url;                    //请求地址
    sds body;                   //请求数据
    ops_http_header* header;    //请求头
    ops_http_header* cur_header;//

    uint32_t pree_id;                           //对端流ID
    //ops_host* host;
}ops_http_request;
RB_HEAD(_ops_http_request_tree, _ops_http_request);
//HTTP流
typedef struct _ops_http_stream {
    RB_ENTRY(_ops_http_stream) entry;           //
    uint32_t id;                                //流id
    struct _ops_http_conn* conn;                //流对应的连接
    union {
        struct {
            http_parser parser;                 //http解析器
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
    struct _ops_global* global;
    uv_tcp_t tcp;               //连接

    uint8_t http_major;                 //协议版本,主
    uint8_t http_minor;                 //协议版本,次

    uint32_t sid;                           //当前分配到的ID
    struct _ops_http_stream_tree stream;   //流
}ops_http_conn;

//配置
typedef struct _ops_config {
    uint16_t web_port;          //web管理端口
    const char* web_password;   //web界面管理密码
    const char* web_username;   //web界面管理账号
    const char* web_base_url;   //web管理主路径, 用于将web管理置于代理子路径后面
    uint16_t bridge_port;       //服务端客户端通信端口
    uint16_t https_proxy_port;  //域名代理https代理监听端口
    uint16_t http_proxy_port;   //域名代理http代理监听端口
    const char* auth_key;       //web api密钥
    const char* db_file;
}ops_config;
//
typedef struct _ops_global {
    struct {
        uv_tcp_t web;                       //web界面
        uv_tcp_t bridge;                    //客户端
        uv_tcp_t https;                     //
        uv_tcp_t http;                      //
    }listen;
    struct messagepool m_mp;                //接收缓冲
    ops_config config;
    struct _ops_auth_tree auth;           //授权数据
    struct _ops_forward_tree forward;     //转发器
    struct _ops_host_tree host;           //域名
    struct _ops_bridge_tree bridge;       //客户端
    struct _ops_http_request_tree request;     //
    uint32_t request_id;                    //
}ops_global;
//web管理连接
typedef struct _ops_web {
    ops_global* global;
    uv_tcp_t tcp;               //连接
    struct http_parser parser;  //解析器
    sds path;
}ops_web;




static uv_loop_t* loop = NULL;

static int _ops_auth_compare(ops_auth* w1, ops_auth* w2) {
    return strcmp(w1->key, w2->key);
}
RB_GENERATE_STATIC(_ops_auth_tree, _ops_auth, entry, _ops_auth_compare)
static int _ops_host_compare(ops_host* w1, ops_host* w2) {
    return strcasecmp(w1->host, w2->host);
}
RB_GENERATE_STATIC(_ops_host_tree, _ops_host, entry, _ops_host_compare)
static int _ops_forward_compare(ops_forward* w1, ops_forward* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_forward_tree, _ops_forward, entry, _ops_forward_compare)
static int _ops_bridge_compare(ops_bridge* w1, ops_bridge* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_bridge_tree, _ops_bridge, entry, _ops_bridge_compare)
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

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
//发送回调
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}


//向客户发送数据
static void bridge_send(ops_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
//----------------------------------------------------------------------------------------------------------------------WEB管理处理
//HTTP应答解析回调
//消息完毕
static int web_on_message_complete(http_parser* p) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//解析到消息体
static int web_on_body(http_parser* p, const char* buf, size_t len) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//解析到域名
static int web_on_url(http_parser* p, const char* buf, size_t len) {
    return 0;
}
static http_parser_settings web_parser_settings = { NULL, web_on_url, NULL, NULL, NULL, NULL, web_on_body, web_on_message_complete, NULL, NULL };
//读取到数据
static void web_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_web* web = (ops_web*)tcp->data;
    ops_global* global = web->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        return;
    }
    http_parser_execute(&web->parser, &web_parser_settings, buf->base, nread);
    free(buf->base);
}
static void web_connection_cb(uv_stream_t* tcp, int status) {
    ops_global* global = (ops_global*)tcp->data;
    ops_web* web = (ops_web*)malloc(sizeof(ops_web));//为tcp bridge申请资源
    if (!web)
        return;
    memset(web, 0, sizeof(*web));
    web->global = global;

    http_parser_init(&web->parser, HTTP_REQUEST);//初始化解析器
    web->parser.data = web;

    uv_tcp_init(loop, &web->tcp);//初始化tcp bridge句柄
    web->tcp.data = web;

    if (uv_accept(tcp, (uv_stream_t*)&web->tcp) == 0) {
        uv_read_start((uv_stream_t*)&web->tcp, alloc_buffer, web_read_cb);
    }

}
//----------------------------------------------------------------------------------------------------------------------HTTP端口处理
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
        return;
    }
    req->data = buf->base;
    return uv_write(req, &conn->tcp, &buf, 1, write_cb);
}
//HTTP应答解析回调
//消息完毕
static int http_on_message_complete(http_parser* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;

    return 0;
}
//解析到消息体
static int http_on_body(http_parser* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (req->body) {
        req->body = sdsnewlen(buf, len);
    }
    else {
        req->body = sdscatlen(req->body, buf, len);
    }
    return 0;
}
//解析到头V
static int http_on_header_value(http_parser* p, const char* buf, size_t len) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    if (req->cur_header->value == NULL)
        req->cur_header->value = sdsempty();
    req->cur_header->value = sdscatlen(req->cur_header->value, buf, len);
    return 0;
}
//解析到头K
static int http_on_header_field(http_parser* p, const char* buf, size_t len) {
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
static int http_on_headers_complete(http_parser* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;
    req->cur_header = NULL;
    //日志
    printf("New Request %s %s\r\n", req->host, req->url);

    //查找域名转发
    ops_host the = {
        .host = req->host
    };
    ops_host* host = RB_FIND(_ops_host_tree, &s->conn->global->host, &the);
    if (host == NULL) {
        return 0;
    }
    //查找目标客户端是否在线
    ops_bridge ths_b = {
        .id = host->dst_id
    };
    ops_bridge* b = RB_FIND(_ops_bridge_tree, &s->conn->global->bridge, &ths_b);
    if (b == NULL) {

        return 0;
    }
    //发起请求
    bridge_send(b, ops_packet_host_ctl, host->id, req->id, NULL, 0);
    return 0;
}
//
static int http_on_url(http_parser* p, const char* buf, size_t len) {
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
static int http_on_message_begin(http_parser* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;

    return 0;
}
static http_parser_settings parser_settings = { http_on_message_begin, http_on_url, NULL, http_on_header_field, http_on_header_value, http_on_headers_complete, http_on_body, http_on_message_complete, NULL, NULL };

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
        http_parser_init(&s->u.h1.parser, HTTP_REQUEST);
        s->u.h1.parser.data = s;
    }
    //创建请求
    ops_http_request* req = (ops_http_request*)malloc(sizeof(*req));
    if (req == NULL) {
        free(s);
        return NULL;
    }
    memset(req, 0, sizeof(*req));
    req->id = conn->global->request_id++;
    req->stream = s;
    RB_INSERT(_ops_http_request_tree, &conn->global->request, req);
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
    uint32_t parsed = http_parser_execute(&s->u.h1.parser, &parser_settings, buf, len);
    if (parsed != len) {
        //处理失败

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

//读取到数据
static void http_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_http_conn* conn = (ops_http_conn*)tcp->data;
    ops_global* global = conn->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        return;
    }
    if (http_conn_data(conn, buf->base, nread)) {
        free(buf->base);
    }
}
//http连接进入
static void http_connection_cb(uv_stream_t* tcp, int status) {
    ops_global* global = (ops_global*)tcp->data;
    ops_http_conn* conn = (ops_http_conn*)malloc(sizeof(ops_http_conn));//为tcp bridge申请资源
    if (!conn)
        return;
    memset(conn, 0, sizeof(*conn));
    conn->global = global;

    uv_tcp_init(loop, &conn->tcp);//初始化tcp bridge句柄
    conn->tcp.data = conn;

    if (uv_accept(tcp, (uv_stream_t*)&conn->tcp) == 0) {
        //默认协议版本是1.1
        conn->http_major = 1;
        conn->http_minor = 1;

        uv_read_start((uv_stream_t*)&conn->tcp, alloc_buffer, http_read_cb);
    }
}
//客户端来的数据
static void host_ctl(ops_bridge* bridge, ops_packet* packet, int size) {
    ops_http_request the = {
    .id = packet->stream_id
    };
    ops_http_request* req = RB_FIND(_ops_http_request_tree, &bridge->global->request, &the);
    if (req == NULL) {
        return;
    }
    //读取类型
    uint8_t type = packet->data[0];
    switch (type)
    {
    case 0x01: {//连接远端成功
        //读取对端流ID
        req->pree_id = ntohl(*(uint32_t*)(&packet->data[1]));
        //生成新请求数据
        //生成数据
        sds d = sdscatprintf(sdsempty(),
            "%s %s HTTP/%d.%d\r\n",
            http_method_str(req->method), req->url, 1, 1);

        ops_http_header* header = req->header;
        while (header) {
            d = sdscatsds(d, header->key);
            d = sdscat(d, ": ");
            //重写host
            //if (strcasecmp(header->key, "host") == 0 && req->host->host_rewrite && req->host->host_rewrite[0] != 0) {
            //    d = sdscat(d, req->host->host_rewrite);
            //}
            //else {
                d = sdscatsds(d, header->value);
            //}
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
        if (req->body) {
            sdsfree(req->body);
            req->body = NULL;
        }
        if (req->url) {
            sdsfree(req->url);
            req->url = NULL;
        }


        //发送数据
        bridge_send(bridge, ops_packet_host_data, packet->service_id, req->pree_id, d, sdslen(d));
        sdsfree(d);
        break;
    }
    default:
        break;
    }
}
static void host_data(ops_bridge* bridge, ops_packet* packet, int size) {
    ops_http_request the = {
        .id = packet->stream_id
    };
    ops_http_request* req = RB_FIND(_ops_http_request_tree, &bridge->global->request, &the);
    if (req == NULL) {
        return;
    }
    http_send(req->stream->conn, packet->data, size);
}
//----------------------------------------------------------------------------------------------------------------------bridge
//向客户发送数据
static void bridge_send(ops_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len) {
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + len;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = type;
    pack->service_id = htonl(service_id);
    pack->stream_id = htonl(stream_id);
    if (data && len) {
        memcpy(pack->data, data, len);
    }
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    req->data = buf->base;
    uv_write(req, &bridge->tcp, &buf, 1, write_cb);
}
//客户端鉴权成功
static void bridge_auth_ok(ops_bridge* bridge) {
    sds pack = sdsnewlen(NULL, 4);//预留数量
    char buf[1 + sizeof(ops_forward_dst) + sizeof(ops_forward_src) + sizeof(ops_host_dst)];
    int count = 0;
    //查询客户端转发服务
    ops_forward* tc = NULL;
    RB_FOREACH(tc, _ops_forward_tree, &bridge->global->forward) {
        //来源
        if (tc->src_id == bridge->id) {
            buf[0] = 1;//类型,转发源
            ops_forward_src src;
            src.port = htons(tc->src.port);
            src.sid = htonl(tc->src.sid);
            src.type = tc->src.type;
            memcpy(&buf[1], &src, sizeof(src));
            pack = sdscatlen(pack, buf, 1 + sizeof(ops_forward_src));
            count++;
        }
        //出口
        if (tc->dst_id == bridge->id) {
            buf[0] = 2;//类型,转发目标
            ops_forward_dst dst;
            dst.port = htons(tc->dst.port);
            dst.sid = htonl(tc->dst.sid);
            dst.type = tc->dst.type;
            memcpy(dst.dst, tc->dst.dst, sizeof(dst.dst));
            memcpy(&buf[1], &dst, sizeof(dst));
            pack = sdscatlen(pack, buf, 1 + sizeof(ops_forward_dst));
            count++;
        }
    }
    *(uint32_t*)pack = htonl(count);
    //下发转发服务
    bridge_send(bridge, ops_packet_forward, 0, 0, pack, sdslen(pack));
    sdsfree(pack);
    //查询主机服务
    pack = sdsnewlen(NULL, 4);//预留数量
    count = 0;
    ops_host* hc = NULL;
    RB_FOREACH(hc, _ops_host_tree, &bridge->global->host) {
        if (hc->dst_id == bridge->id) {
            ops_host_dst dst;
            dst.port = htons(hc->dst.port);
            dst.sid = htonl(hc->dst.sid);
            dst.type = hc->dst.type;
            memcpy(dst.dst, hc->dst.dst, sizeof(dst.dst));
            memcpy(&buf, &dst, sizeof(dst));
            pack = sdscatlen(pack, buf, sizeof(ops_host_dst));
            count++;
        }
    }
    *(uint32_t*)pack = htonl(count);
    //下发主机服务
    bridge_send(bridge, ops_packet_host, 0, 0, pack, sdslen(pack));
    sdsfree(pack);


}
//收到客户端数据
static void bridge_on_data(ops_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
    packet->service_id = ntohl(packet->service_id);
    packet->stream_id = ntohl(packet->stream_id);
    size -= sizeof(ops_packet);
    switch (packet->type)
    {
    case ops_packet_auth: {
        //读取key长度
        uint16_t key_len = ntohs(*(uint16_t*)(&packet->data));
        packet->data[key_len + 2] = 0;
        ops_auth _auth = {
            .key = packet->data + 2
        };
        ops_auth* auth = RB_FIND(_ops_auth_tree, &bridge->global->auth, &_auth);
        if (auth == NULL) {
            bridge_send(bridge, ops_packet_auth, 0, 0, NULL, 0);
        }
        else {
            ops_forward ths = {
                .id = auth->id
            };
            //查找ID是否存在
            ops_bridge* p = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths);
            if (p != NULL) {
                bridge_send(bridge, ops_packet_auth, 0, 0, NULL, 0);
            }
            else {
                char buf[1];
                buf[0] = 1;//鉴权成功
                bridge_send(bridge, ops_packet_auth, 0, 0, buf, 1);
                //记录客户端
                bridge->id = auth->id;
                RB_INSERT(_ops_bridge_tree, &bridge->global->bridge, bridge);
                bridge_auth_ok(bridge);
            }
        }
        break;
    }
    case ops_packet_ping: {

        break;
    }
    case ops_packet_forward_ctl: {//转发控制指令
        //查找服务
        ops_forward ths = {
               .id = packet->service_id
        };
        ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
        if (p == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        uint8_t type = packet->data[0];
        switch (type)
        {
        case 0x01: {//发起请求
            //查找目标客户端是否存在
            ops_bridge ths_b = {
                    .id = p->dst_id
            };
            ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
            if (b == NULL) {
                bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
                break;
            }
            //发送
            bridge_send(b, ops_packet_forward_ctl, packet->service_id, packet->stream_id, packet->data, size);
            break;
        }
        case 0x02: {
            //查找来源客户端是否存在
            ops_bridge ths_b = {
                    .id = p->src_id
            };
            ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
            if (b == NULL) {
                bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
                break;
            }
            //发送
            bridge_send(b, ops_packet_forward_ctl, packet->service_id, packet->stream_id, packet->data, size);
            break;
        }
        default:
            break;
        }
        break;
    }
    case ops_packet_forward_data_remote: {//远程来的转发数据
        //查找服务
        ops_forward ths = {
               .id = packet->service_id
        };
        ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
        if (p == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //查找来源客户端是否存在
        ops_bridge ths_b = {
                .id = p->src_id
        };
        ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
        if (b == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //发送
        bridge_send(b, ops_packet_forward_data_remote, packet->service_id, packet->stream_id, packet->data, size);
        break;
    }
    case ops_packet_forward_data_local: {//本地来的转发数据
        //查找服务
        ops_forward ths = {
               .id = packet->service_id
        };
        ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
        if (p == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //查找目标客户端是否存在
        ops_bridge ths_b = {
                .id = p->dst_id
        };
        ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
        if (b == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //发送
        bridge_send(b, ops_packet_forward_data_local, packet->service_id, packet->stream_id, packet->data, size);
        break;
    }
    case ops_packet_host_ctl: {//域名控制命令
        host_ctl(bridge, packet, size);
        break;
    }
    case ops_packet_host_data: {//域名转发数据
        host_data(bridge, packet, size);
        break;
    }
    default:
        break;
    }


}
//关闭
static void bridge_close_cb(uv_handle_t* handle) {
    ops_bridge* bridge = (ops_bridge*)handle->data;


    databuffer_clear(&bridge->m_buffer, &bridge->global->m_mp);
    free(bridge);
}
static void bridge_shutdown_cb(uv_shutdown_t* req, int status) {
    ops_bridge* bridge = (ops_bridge*)req->data;
    uv_close(&bridge->tcp, bridge_close_cb);
    free(req);
}
//读取到数据
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_bridge* bridge = (ops_bridge*)tcp->data;
    ops_global* global = bridge->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, bridge_close_cb);
        }
        else {
            //shutdown
            uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
            if (req != NULL) {
                memset(req, 0, sizeof(*req));
                req->data = bridge;
                uv_shutdown(req, tcp, bridge_shutdown_cb);
            }
            else {
                //分配内存失败,直接强制关闭
                uv_close(tcp, bridge_close_cb);
            }
        }
        //从句柄树中移除
        if (bridge->id) {
            RB_REMOVE(_ops_bridge_tree, &bridge->global->bridge, bridge);
        }
        return;
    }
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &global->m_mp, buf->base, nread);
    for (;;) {
        int size = databuffer_readheader(&bridge->m_buffer, &global->m_mp, 4);
        if (size < 0) {
            return;
        }
        char* temp = malloc(size);
        databuffer_read(&bridge->m_buffer, &global->m_mp, temp, size);
        bridge_on_data(bridge, temp, size);
        databuffer_reset(&bridge->m_buffer);
    }
}
//连接进入
static void bridge_connection_cb(uv_stream_t* tcp, int status) {
    ops_global* global = (ops_global*)tcp->data;
    ops_bridge* bridge = (ops_bridge*)malloc(sizeof(ops_bridge));//为tcp bridge申请资源
    if (!bridge)
        return;
    memset(bridge, 0, sizeof(*bridge));
    bridge->global = global;

    uv_tcp_init(loop, &bridge->tcp);//初始化tcp bridge句柄
    bridge->tcp.data = bridge;

    if (uv_accept(tcp, (uv_stream_t*)&bridge->tcp) == 0) {
        //新客户
        printf("New Client\r\n");
        uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);
    }
}
//----------------------------------------------------------------------------------------------------------------------data
//用户发生改变
static void data_key_add(ops_global* global, uint16_t id, const char* key) {
    ops_auth* auth = malloc(sizeof(*auth));
    if (auth == NULL)
        return;
    memset(auth, 0, sizeof(*auth));
    auth->id = id;
    auth->key = strdup(key);
    RB_INSERT(_ops_auth_tree, &global->auth, auth);
}
static void data_key_del(ops_global* global, const char* key) {
    ops_auth _auth = {
           .key = key
    };
    ops_auth* auth = RB_FIND(_ops_auth_tree, &global->auth, &_auth);
    if (auth == NULL) {
        return;
    }
    free(auth->key);
    //踢出相关客户端

    RB_REMOVE(_ops_auth_tree, &global->auth, auth);
}
//通道发生改变
static void data_forward_add(ops_global* global, uint32_t id, uint16_t src_id, uint16_t dst_id, uint8_t type, uint16_t src_port, const char* dst, uint16_t dst_port) {
    ops_forward* forward = malloc(sizeof(*forward));
    if (forward == NULL)
        return;
    memset(forward, 0, sizeof(*forward));
    forward->id = id;
    forward->src_id = src_id;
    forward->dst_id = dst_id;
    forward->src.sid = id;
    forward->dst.sid = id;
    forward->src.type = type;
    forward->src.port = src_port;
    forward->dst.type = type;
    forward->dst.port = dst_port;
    strncpy(forward->dst.dst, dst, sizeof(forward->dst.dst) - 1);
    forward->dst.dst[sizeof(forward->dst.dst) - 1] = 0;
    RB_INSERT(_ops_forward_tree, &global->forward, forward);
    //下发到相关通道

}
static void data_forward_del(ops_global* global, uint32_t id) {
    ops_forward ths = {
    .id = id
    };
    //查找ID是否存在
    ops_forward* forward = RB_FIND(_ops_forward_tree, &global->forward, &ths);
    if (forward == NULL) {
        return;
    }
    //通知相关客户端当前服务已移除


    RB_REMOVE(_ops_forward_tree, &global->forward, forward);
}
//
static void data_host_add(ops_global* global, uint32_t id, const char* src_host, uint16_t dst_id, uint8_t type, const char* dst, uint16_t dst_port, const char* host_rewrite) {
    ops_host* host = malloc(sizeof(*host));
    if (host == NULL)
        return;
    memset(host, 0, sizeof(*host));
    host->id = id;
    host->host = strdup(src_host);
    host->dst_id = dst_id;
    host->dst.sid = id;
    host->dst.type = type;
    host->dst.port = dst_port;
    if (host_rewrite) {
        host->host_rewrite = strdup(host_rewrite);
    }
    strncpy(host->dst.dst, dst, sizeof(host->dst.dst) - 1);
    host->dst.dst[sizeof(host->dst.dst) - 1] = 0;
    RB_INSERT(_ops_host_tree, &global->host, host);

    //下发
}
struct data_settings data_settings = { data_key_add, data_key_del, data_forward_add, data_forward_del, data_host_add };
//----------------------------------------------------------------------------------------------------------------------
//全局初始化
static int init_global(ops_global* global) {
    struct sockaddr_in _addr;
    //初始化数据
    data_init(global->config.db_file, global, &data_settings);
    //web管理
    global->listen.web.data = global;
    uv_tcp_init(loop, &global->listen.web);
    uv_ip4_addr("0.0.0.0", global->config.web_port, &_addr);
    uv_tcp_bind(&global->listen.web, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.web, DEFAULT_BACKLOG, web_connection_cb);

    //客户端桥接
    global->listen.bridge.data = global;
    uv_tcp_init(loop, &global->listen.bridge);
    uv_ip4_addr("0.0.0.0", global->config.bridge_port, &_addr);
    uv_tcp_bind(&global->listen.bridge, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.bridge, DEFAULT_BACKLOG, bridge_connection_cb);

    //http端口
    global->listen.http.data = global;
    uv_tcp_init(loop, &global->listen.http);
    uv_ip4_addr("0.0.0.0", global->config.http_proxy_port, &_addr);
    uv_tcp_bind(&global->listen.http, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.http, DEFAULT_BACKLOG, http_connection_cb);

    //https端口
    global->listen.https.data = global;
    uv_tcp_init(loop, &global->listen.https);
    uv_ip4_addr("0.0.0.0", global->config.https_proxy_port, &_addr);
    uv_tcp_bind(&global->listen.https, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.https, DEFAULT_BACKLOG, http_connection_cb);
}
//加载配置
static load_config(ops_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.db_file = "data.db";
    global->config.bridge_port = 1664;
    global->config.web_port = 8088;
    global->config.https_proxy_port = 443;
    global->config.http_proxy_port = 80;

    //从命令行加载参数
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            i++;
            global->config.bridge_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-w") == 0) {
            i++;
            global->config.web_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-h") == 0) {
            i++;
            global->config.http_proxy_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-s") == 0) {
            i++;
            global->config.https_proxy_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-d") == 0) {
            i++;
            global->config.db_file = strdup(argv[i]);
        }
    }
}

int main(int argc, char* argv[]) {
    loop = uv_default_loop();
    //启动监听
    ops_global* global = (ops_global*)malloc(sizeof(*global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //加载参数
    load_config(global, argc, argv);
    //初始化
    init_global(global);
    //
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

