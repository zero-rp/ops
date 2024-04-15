#include <uv.h>
#include <cJSON.h>
#include <http_parser.h>
#include <uv/tree.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/base64.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
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
    RB_ENTRY(_ops_host) entry;       //
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
//VPC网络
typedef struct _ops_vpc {
    RB_ENTRY(_ops_vpc) entry;            //
    uint16_t id;                             //网络编号
    uint8_t ipv4[4];                         //ipv4网段
    uint8_t ipv6[16];                        //ipv6网段
}ops_vpc;
RB_HEAD(_ops_vpc_tree, _ops_vpc);
//VPC成员
typedef struct _ops_members {
    RB_ENTRY(_ops_members) entry;                //
    uint16_t bid;                               //客户ID
    ops_vpc* vpc;                               //关联的VPC
    uint32_t id;                                //成员编号
    uint8_t ipv4[4];                            //ipv4地址
    uint8_t ipv6[16];                           //ipv6地址
}ops_members;
RB_HEAD(_ops_members_tree, _ops_members);
//VPC路由
typedef struct _ops_route_v4 {
    RB_ENTRY(_ops_route_v4) entry;              //
    uint16_t id;                                //客户ID
    uint32_t mid;                               //成员ID
    uint8_t ip[4];                              //地址
}ops_route_v4;
RB_HEAD(_ops_route_v4_tree, _ops_route_v4);
typedef struct _ops_route_v6 {
    RB_ENTRY(_ops_route_v6) entry;              //
    uint16_t id;                                //客户ID
    uint32_t mid;                               //成员ID
    uint8_t ip[16];                             //地址
}ops_route_v6;
RB_HEAD(_ops_route_v6_tree, _ops_route_v6);
//客户端
typedef struct _ops_bridge {
    RB_ENTRY(_ops_bridge) entry;        //
    uint16_t id;                        //客户端ID
    struct _ops_global* global;
    uv_tcp_t tcp;                       //连接
    struct databuffer m_buffer;         //接收缓冲
    uint32_t ping;                      //延迟
}ops_bridge;
RB_HEAD(_ops_bridge_tree, _ops_bridge);
//授权信息
typedef struct _ops_key {
    RB_ENTRY(_ops_key) entry;          //
    const char* key;                    //
    uint16_t id;                        //客户端ID
}ops_key;
RB_HEAD(_ops_key_tree, _ops_key);
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
    sds host;                                   //主机
    sds url;                                    //请求地址
    sds body;                                   //请求数据
    ops_http_header* header;                    //请求头
    ops_http_header* cur_header;                //

    ops_host* service;
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
    const char* admin_user;
    const char* admin_pass;
    const char* db_file;
}ops_config;
//授权信息
typedef struct _ops_auth {
    RB_ENTRY(_ops_auth) entry;          //
    char token[65];                     //
    time_t time;                        //时间
}ops_auth;
RB_HEAD(_ops_auth_tree, _ops_auth);
//全局
typedef struct _ops_global {
    struct {
        struct {
            uv_tcp_t tcp;
            struct _ops_auth_tree auth;
        } web;//web界面
        uv_tcp_t bridge;                    //客户端
        uv_tcp_t http;                      //
        struct {
            SSL_CTX* ctx;
            uv_tcp_t tcp;                     //
        }https;
    }listen;
    struct messagepool m_mp;                //接收缓冲
    ops_config config;
    struct _ops_key_tree key;               //授权数据
    struct _ops_forward_tree forward;       //转发器
    struct _ops_host_tree host;             //域名
    struct _ops_vpc_tree vpc;               //虚拟网络
    struct _ops_members_tree members;       //虚拟网络成员
    struct _ops_route_v4_tree route_v4;     //IPv4路由表
    struct _ops_route_v6_tree route_v6;     //IPv6路由表
    struct _ops_bridge_tree bridge;         //客户端
    struct _ops_http_request_tree request;  //
    uint32_t request_id;                    //
    struct {
        uint32_t bridge_count;              //客户端数量
        uint32_t bridge_online;             //在线客户端数量

    } stat;
}ops_global;
//web管理连接,只使用http1
typedef struct _ops_web {
    ops_global* global;
    uv_tcp_t tcp;                               //连接
    struct http_parser parser;                  //解析器
    sds url;                                    //请求地址
    sds body;                                   //请求数据
}ops_web;

static uv_loop_t* loop = NULL;

static int _ops_auth_compare(ops_auth* w1, ops_auth* w2) {
    return strcmp(w1->token, w2->token);
}
RB_GENERATE_STATIC(_ops_auth_tree, _ops_auth, entry, _ops_auth_compare)
static int _ops_key_compare(ops_key* w1, ops_key* w2) {
    return strcmp(w1->key, w2->key);
}
RB_GENERATE_STATIC(_ops_key_tree, _ops_key, entry, _ops_key_compare)
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
static int _ops_vpc_compare(ops_vpc* w1, ops_vpc* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_vpc_tree, _ops_vpc, entry, _ops_vpc_compare)
static int _ops_members_compare(ops_members* w1, ops_members* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_members_tree, _ops_members, entry, _ops_members_compare)
static int _ops_route_v4_compare(ops_route_v4* w1, ops_route_v4* w2) {
    if (*(uint32_t*)(&w1->ip) < *(uint32_t*)(&w2->ip)) return -1;
    if (*(uint32_t*)(&w1->ip) > *(uint32_t*)(&w2->ip)) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_route_v4_tree, _ops_route_v4, entry, _ops_route_v4_compare)
static int _ops_route_v6_compare(ops_route_v6* w1, ops_route_v6* w2) {
    if (*(uint32_t*)(&w1->ip[0]) < *(uint32_t*)(&w2->ip[0])) return -1;
    if (*(uint32_t*)(&w1->ip[0]) > *(uint32_t*)(&w2->ip[0])) return 1;
    if (*(uint32_t*)(&w1->ip[4]) < *(uint32_t*)(&w2->ip[4])) return -1;
    if (*(uint32_t*)(&w1->ip[4]) > *(uint32_t*)(&w2->ip[4])) return 1;
    if (*(uint32_t*)(&w1->ip[8]) < *(uint32_t*)(&w2->ip[8])) return -1;
    if (*(uint32_t*)(&w1->ip[8]) > *(uint32_t*)(&w2->ip[8])) return 1;
    if (*(uint32_t*)(&w1->ip[12]) < *(uint32_t*)(&w2->ip[12])) return -1;
    if (*(uint32_t*)(&w1->ip[12]) > *(uint32_t*)(&w2->ip[12])) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_route_v6_tree, _ops_route_v6, entry, _ops_route_v6_compare)
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

static unsigned char hex_val(char hex) {
    if ((hex >= '0') && (hex <= '9'))
        return (hex - '0');
    else if ((hex >= 'a') && (hex <= 'f'))
        return (hex - 'a' + 10);
    else if ((hex >= 'A') && (hex <= 'F'))
        return (hex - 'A' + 10);
    return 0;
}
static unsigned char str2hex(char* str, unsigned char len, unsigned char buf[]) {
    int i;
    unsigned char sz, j;
    char* p;
    p = str;
    if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X'))
        p += 2;
    sz = len >> 1;
    j = 0;
    for (i = 0; i < sz; i++) {
        buf[i] = (hex_val(p[j++]) << 4);
        buf[i] |= hex_val(p[j++]);
    }
    return sz;
}
static unsigned char hex2str(unsigned char* buf, unsigned char len, char* str) {
    unsigned char i, j;
    unsigned char b;
    j = 0;
    for (i = 0; i < len; i++) {
        b = buf[i] >> 4;
        if (b <= 9)
            str[j++] = '0' + b;
        else {
            str[j++] = 'a' + b - 10;
        }
        b = buf[i] & 0x0f;
        if (b <= 9)
            str[j++] = '0' + b;
        else {
            str[j++] = 'a' + b - 10;
        }
    }
    str[j] = 0;
    return j;
}

//向客户发送数据
static void bridge_send(ops_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
//----------------------------------------------------------------------------------------------------------------------WEB管理处理
#if 1
//发送回调
static void web_write_cb(uv_write_t* req, int status) {
    sdsfree(req->data);
}
//发送原始数据
static int web_respose_raw(ops_web* web, sds data) {
    //转发数据到远程
    uv_buf_t buf[] = { 0 };
    buf->len = sdslen(data);
    buf->base = data;
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        sdsfree(buf->base);
        return -1;
    }
    req->data = data;
    return uv_write(req, &web->tcp, &buf, 1, web_write_cb);
}
//
static void web_respose_html(ops_web* web, const char* html, int len) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: text/html;charset=utf-8;\r\n"
        "\r\n",
        200, "OK", len);
    //数据
    data = sdscatlen(data, html, len);
    web_respose_raw(web, data);
}
//
static void web_respose_chunked_header(ops_web* web) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Transfer-Encoding:chunked\r\n"
        //"Content-Type: text/html;charset=utf-8;\r\n"
        "\r\n",
        200, "OK");
    web_respose_raw(web, data);
}
static void web_respose_chunked_data(ops_web* web, char* buf, int len) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "%zx\r\n", len);
    if (buf && len) {
        data = sdscatlen(data, buf, len);
    }
    data = sdscat(data, "\r\n");
    web_respose_raw(web, data);
}
//跨域处理
static void web_respose_cors(ops_web* web) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Access-Control-Allow- Methods: POST\r\n"
        "Access-Control-Max-Age: 1728000\r\n"
        "\r\n",
        204, "OK");
    web_respose_raw(web, data);
}
//web管理应答
static void web_respose_json(ops_web* web, int code, const char* msg, cJSON* json) {
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "code", code);
    cJSON_AddStringToObject(resp, "msg", msg);
    cJSON_AddItemToObject(resp, "data", json);
    char* str = cJSON_Print(resp);
    int str_len = strlen(str);
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: application/json;charset=utf-8;\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Access-Control-Allow- Methods: POST\r\n"
        "Access-Control-Max-Age: 1728000\r\n"
        "\r\n",
        200, "OK", str_len);

    //数据
    data = sdscatlen(data, str, str_len);
    web_respose_raw(web, data);
}


struct web_read {
    uv_buf_t buf;
    uv_file file;
    ops_web* web;
};

void web_on_read(uv_fs_t* req) {
    struct web_read* wr = req->data;
    uv_fs_req_cleanup(req);
    if (req->result < 0) {
        //读取失败
        //发送结束包
        web_respose_chunked_data(wr->web, NULL, 0);
    }
    //读取完毕
    else if (req->result == 0) {
        //发送结束包
        web_respose_chunked_data(wr->web, NULL, 0);
        //关闭文件
        uv_fs_t close_req;
        uv_fs_close(loop, &close_req, wr->file, NULL);
    }
    //读取到数据
    else if (req->result > 0) {
        //发送数据块
        web_respose_chunked_data(wr->web, wr->buf.base, req->result);
        //继续读取
        uv_fs_read(loop, req, wr->file, &wr->buf, 1, -1, web_on_read);
    }
}
//
void web_fs_cb(uv_fs_t* req) {
    ops_web* web = req->data;
    if (req->result != -1) {
        //文件打开成功,发送响应头
        web_respose_chunked_header(web);
        //开始读取数据
        uv_fs_t* read_req = (uv_fs_t*)malloc(sizeof(*read_req));
        struct web_read* wr = (struct web_read*)malloc(sizeof(struct web_read));
        wr->web = web;
        wr->buf.len = 1024;
        wr->buf.base = malloc(wr->buf.len);
        wr->file = req->result;
        read_req->data = wr;
        uv_fs_read(loop, read_req, req->result, &wr->buf, 1, -1, web_on_read);
    }
    else {
        //打开文件失败

    }
    uv_fs_req_cleanup(req);
    free(req);
}
//
void web_respose_file(ops_web* web, const char* file) {
    uv_fs_t* req = (uv_fs_t*)malloc(sizeof(*req));
    if (!req) {
        web_respose_html(web, "404", 3);
        return;
    }
    req->data = web;
    char path[512] = { 0 };
    snprintf(path, sizeof(path), "%s/%s", "./web", file);
    if (uv_fs_open(loop, req, path, 0, 0, web_fs_cb) != 0) {
        web_respose_html(web, "404", 3);
    }
}
//web管理请求
static void web_on_request(ops_web* web, cJSON* body) {
    if (web->parser.method == HTTP_OPTIONS) {
        return web_respose_cors(web);
    }
    cJSON* data = cJSON_CreateObject();
    char* url = web->url;
    if (url[0] != '/')
        goto err;
    switch (url[1])
    {
    case 0x00: {
        return web_respose_file(web, "index.html");
    }
    case 'l': {
        url++;
        if (strcmp(url, "layui/css/layui.css") == 0 || strcmp(url, "layui/layui.js") == 0 || strcmp(url, "layui/font/iconfont.woff2") == 0) {
            return web_respose_file(web, url);
        }
        else {
            goto err;
        }
        break;
    }
    case 'a':
        if (url[2] != 'p' || url[3] != 'i' || url[4] != '/')
            goto err;
        else
            url += 5;
        break;
    default:
        goto err;
        break;
    }
    if (!body) {
        return web_respose_json(web, -2, "NO BODY", data);
    }
    // 登录
    if (url[0] == 'a' && url[1] == 'u' && url[2] == 't' && url[3] == 'h') {
        cJSON* user = cJSON_GetObjectItem(body, "user");
        cJSON* pass = cJSON_GetObjectItem(body, "pass");
        if (!user || !pass || !user->valuestring || !pass->valuestring) {
            return web_respose_json(web, -3, "user or pass is null", data);
        }
        if (strcmp(user->valuestring, web->global->config.admin_user) != 0 || strcmp(pass->valuestring, web->global->config.admin_pass) != 0) {
            return web_respose_json(web, -4, "user or pass is error", data);
        }
        //生成token
        char buf[16];
        RAND_bytes(buf, 16);
        //记录TOKEN
        ops_auth* auth = (ops_auth*)malloc(sizeof(*auth));
        memset(auth, 0, sizeof(*auth));
        hex2str(buf, 16, auth->token);
        auth->time = time(NULL);
        RB_INSERT(_ops_auth_tree, &web->global->listen.web.auth, auth);
        cJSON_AddStringToObject(data, "token", auth->token);
        goto ok;
    }
    //鉴权
    cJSON* token = cJSON_GetObjectItem(body, "token");
    if (!token || !token->valuestring) {
        return web_respose_json(web, 403, "NO AUTH", data);
    }
    ops_auth _auth = { 0 };
    strncpy(_auth.token, token->valuestring, 32);
    ops_auth* auth = RB_FIND(_ops_auth_tree, &web->global->listen.web.auth, &_auth);
    if (!auth || (time(NULL) - auth->time) > 60 * 30) {
        return web_respose_json(web, 403, "NO AUTH", data);
    }
    auth->time = time(NULL);
    //服务器信息
    if (strcmp(url, "info") == 0) {
        cJSON* config = cJSON_AddObjectToObject(data, "config");
        cJSON_AddNumberToObject(config, "web_port", web->global->config.web_port);
        cJSON_AddNumberToObject(config, "http_port", web->global->config.http_proxy_port);
        cJSON_AddNumberToObject(config, "https_port", web->global->config.https_proxy_port);
        cJSON* stat = cJSON_AddObjectToObject(data, "stat");
        cJSON_AddNumberToObject(stat, "bridge_count", web->global->stat.bridge_count);
        cJSON_AddNumberToObject(stat, "bridge_online", web->global->stat.bridge_online);
        goto ok;
    }
    //客户列表
    else if (strcmp(url, "bridge") == 0) {
        cJSON* list = data_bridge_get();
        cJSON_AddItemToObject(data, "list", list);
        goto ok;
    }
    //添加客户端
    else if (strcmp(url, "bridge_add") == 0) {
        //生成key
        char buf[16];
        char key[33];
        RAND_bytes(buf, 16);
        hex2str(buf, 16, key);
        cJSON* _info = cJSON_GetObjectItem(body, "info");
        //记录数据
        if (data_bridge_add(key, _info ? _info->valuestring : NULL) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "add error", data);
        }
    }
    //删除客户端
    else if (strcmp(url, "bridge_del") == 0) {
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        if (data_bridge_del(id->valueint) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "del error", data);
        }
    }
    //转发列表
    else if (strcmp(url, "forward") == 0) {
        cJSON* list = data_forward_get();
        cJSON_AddItemToObject(data, "list", list);

        goto ok;
    }
    //添加转发
    else if (strcmp(url, "forward_add") == 0) {
        cJSON* src_id = cJSON_GetObjectItem(body, "src_id");
        if (!src_id || src_id->valueint < 1)
            goto err_data;
        cJSON* dst_id = cJSON_GetObjectItem(body, "dst_id");
        if (!dst_id || dst_id->valueint < 1)
            goto err_data;
        cJSON* type = cJSON_GetObjectItem(body, "type");
        if (!type || type->valueint < 1)
            goto err_data;
        cJSON* src_port = cJSON_GetObjectItem(body, "src_port");
        if (!src_port || src_port->valueint < 1)
            goto err_data;
        cJSON* dst = cJSON_GetObjectItem(body, "dst");
        if (!dst || !dst->valuestring)
            goto err_data;
        cJSON* dst_port = cJSON_GetObjectItem(body, "dst_port");
        if (!dst_port || dst_port->valueint < 1)
            goto err_data;
        cJSON* bind = cJSON_GetObjectItem(body, "bind");
        cJSON* info = cJSON_GetObjectItem(body, "info");

        if (data_forward_add(src_id->valueint, dst_id->valueint, type->valueint, src_port->valueint, bind ? bind->valuestring : "", dst->valuestring, dst_port->valueint, info ? info->valuestring : "") == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "add error", data);
        }
    }
    //删除转发
    else if (strcmp(url, "forward_del") == 0) {
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        if (data_forward_del(id->valueint) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "del error", data);
        }
    }
    //主机列表
    else if (strcmp(url, "host") == 0) {
        cJSON* list = data_host_get();
        cJSON_AddItemToObject(data, "list", list);

        goto ok;
    }
    //添加主机
    else if (strcmp(url, "host_add") == 0) {
        cJSON* host = cJSON_GetObjectItem(body, "host");
        if (!host || !host->valuestring)
            goto err_data;
        cJSON* dst_id = cJSON_GetObjectItem(body, "dst_id");
        if (!dst_id || dst_id->valueint < 1)
            goto err_data;
        cJSON* type = cJSON_GetObjectItem(body, "type");
        if (!type || type->valueint < 1)
            goto err_data;
        cJSON* dst = cJSON_GetObjectItem(body, "dst");
        if (!dst || !dst->valuestring)
            goto err_data;
        cJSON* dst_port = cJSON_GetObjectItem(body, "dst_port");
        if (!dst_port || dst_port->valueint < 1)
            goto err_data;
        cJSON* host_rewrite = cJSON_GetObjectItem(body, "host_rewrite");
        if (!host_rewrite || !host_rewrite->valuestring)
            goto err_data;
        cJSON* bind = cJSON_GetObjectItem(body, "bind");
        cJSON* info = cJSON_GetObjectItem(body, "info");

        if (data_host_add(host->valuestring, dst_id->valueint, type->valueint, bind ? bind->valuestring : "", dst->valuestring, dst_port->valueint, host_rewrite ? host_rewrite->valuestring : "", info ? info->valuestring : "") == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "add error", data);
        }
    }
    //删除主机
    else if (strcmp(url, "host_del") == 0) {
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        if (data_host_del(id->valueint) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "del error", data);
        }
    }
    //虚拟网络列表
    else if (strcmp(url, "vpc") == 0) {
        cJSON* list = data_vpc_get();
        cJSON_AddItemToObject(data, "list", list);

        goto ok;
    }
    //添加虚拟网络
    else if (strcmp(url, "vpc_add") == 0) {
        cJSON* ipv4 = cJSON_GetObjectItem(body, "ipv4");
        if (!ipv4 || !ipv4->valuestring)
            goto err_data;
        cJSON* ipv6 = cJSON_GetObjectItem(body, "ipv6");
        cJSON* info = cJSON_GetObjectItem(body, "info");

        if (data_vpc_add(ipv4->valuestring, ipv6 ? ipv6->valuestring : "", info ? info->valuestring : "") == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "add error", data);
        }
    }
    //成员列表
    else if (strcmp(url, "member") == 0) {
        cJSON* list = data_member_get();
        cJSON_AddItemToObject(data, "list", list);

        goto ok;
    }
    //添加成员
    else if (strcmp(url, "member_add") == 0) {
        cJSON* bid = cJSON_GetObjectItem(body, "bid");
        if (!bid || bid->valueint < 1)
            goto err_data;
        cJSON* vid = cJSON_GetObjectItem(body, "vid");
        if (!vid || vid->valueint < 1)
            goto err_data;
        cJSON* ipv4 = cJSON_GetObjectItem(body, "ipv4");
        if (!ipv4 || !ipv4->valuestring)
            goto err_data;
        cJSON* ipv6 = cJSON_GetObjectItem(body, "ipv6");
        cJSON* info = cJSON_GetObjectItem(body, "info");

        if (data_member_add(bid->valueint, vid->valueint, ipv4->valuestring, ipv6 ? ipv6->valuestring : "", info ? info->valuestring : "") == 0) {
            goto ok;
        }
        else {
            return web_respose_json(web, -1, "add error", data);
        }
    }

ok:
    return web_respose_json(web, 0, "ok", data);
err_data:
    return web_respose_json(web, -1, "data error", data);
err://未识别的地址
    return web_respose_json(web, 404, "NO URL", data);
}
//HTTP应答解析回调
//消息完毕
static int web_on_message_complete(http_parser* p) {
    ops_web* web = (ops_web*)p->data;
    cJSON* body = NULL;
    if (web->body) {
        body = cJSON_ParseWithLength(web->body, sdslen(web->body));
    }
    web_on_request(web, body);
    cJSON_free(body);
    //重置请求
    if (web->url) {
        sdsfree(web->url);
        web->url = NULL;
    }
    if (web->body) {
        sdsfree(web->body);
        web->body = NULL;
    }
    return 0;
}
//解析到消息体
static int web_on_body(http_parser* p, const char* buf, size_t len) {
    ops_web* web = (ops_web*)p->data;
    if (web->body == NULL) {
        web->body = sdsnewlen(buf, len);
    }
    else {
        web->body = sdscatlen(web->body, buf, len);
    }
    return 0;
}
//解析到域名
static int web_on_url(http_parser* p, const char* buf, size_t len) {
    ops_web* web = (ops_web*)p->data;
    if (web->url == NULL) {
        web->url = sdsnewlen(buf, len);
    }
    else {
        web->url = sdscatlen(web->url, buf, len);
    }
    return 0;
}
static http_parser_settings web_parser_settings = { NULL, web_on_url, NULL, NULL, NULL, NULL, web_on_body, web_on_message_complete, NULL, NULL };
//连接关闭
static void web_close_cb(uv_handle_t* handle) {
    ops_web* web = (ops_web*)handle->data;
    if (web->url) {
        sdsfree(web->url);
    }
    if (web->body) {
        sdsfree(web->body);
    }
    free(web);
}
static void web_shutdown_cb(uv_shutdown_t* req, int status) {
    ops_web* web = (ops_web*)req->data;
    uv_close(&web->tcp, web_close_cb);
    free(req);
}
//读取到数据
static void web_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_web* web = (ops_web*)tcp->data;
    ops_global* global = web->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, web_close_cb);
        }
        else {
            //shutdown
            uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
            if (req != NULL) {
                memset(req, 0, sizeof(*req));
                req->data = web;
                uv_shutdown(req, tcp, web_shutdown_cb);
            }
            else {
                //分配内存失败,直接强制关闭
                uv_close(tcp, web_close_cb);
            }
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

    uv_tcp_init(loop, &web->tcp);//初始化tcp bridge句柄
    web->tcp.data = web;

    if (uv_accept(tcp, (uv_stream_t*)&web->tcp) == 0) {
        http_parser_init(&web->parser, HTTP_REQUEST);//初始化解析器
        web->parser.data = web;

        uv_read_start((uv_stream_t*)&web->tcp, alloc_buffer, web_read_cb);
    }
}
#endif
//----------------------------------------------------------------------------------------------------------------------HTTP端口处理
#if 1
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
//HTTP应答解析回调
//消息完毕
static int http_on_message_complete(http_parser* p) {
    ops_http_stream* s = (ops_http_stream*)p->data;
    ops_http_request* req = s->request;

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
    //给请求关联对应的服务
    req->service = host;
    //发起请求
    bridge_send(b, ops_packet_host_ctl, host->id, req->id, NULL, 0);

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
    req->method = p->method;
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
    ops_global* global = conn->global;
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
        uint32_t pree_id = ntohl(*(uint32_t*)(&packet->data[1]));
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
        bridge_send(bridge, ops_packet_host_data, packet->service_id, pree_id, d, sdslen(d));
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
#endif
//----------------------------------------------------------------------------------------------------------------------https
//https连接进入
static void https_connection_cb(uv_stream_t* tcp, int status) {
    ops_global* global = (ops_global*)tcp->data;
    ops_http_conn* conn = (ops_http_conn*)malloc(sizeof(ops_http_conn));//为tcp bridge申请资源
    if (!conn)
        return;
    memset(conn, 0, sizeof(*conn));
    conn->global = global;

    uv_tcp_init(loop, &conn->tcp);//初始化tcp句柄
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
//----------------------------------------------------------------------------------------------------------------------forward
#if 1
static void forward_ctl(ops_bridge* bridge, ops_packet* packet, int size) {
    //查找服务
    ops_forward ths = {
           .id = packet->service_id
    };
    ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
    if (p == NULL) {
        bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
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
            uint8_t buf[2];
            buf[0] = 0x02;//来自目标的命令
            buf[1] = 0x01;//错误
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, buf, sizeof(buf));
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
            //来源已经不存在
            uint8_t buf[2];
            buf[0] = 0x03;//来自来源的命令
            buf[1] = 0x01;//错误
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, buf, sizeof(buf));
            break;
        }
        //发送
        bridge_send(b, ops_packet_forward_ctl, packet->service_id, packet->stream_id, packet->data, size);
        break;
    }
    default:
        break;
    }
}
static void forward_data_remote(ops_bridge* bridge, ops_packet* packet, int size) {
    ops_forward ths = {
               .id = packet->service_id
    };
    ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
    if (p == NULL) {
        bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
    }
    //查找来源客户端是否存在
    ops_bridge ths_b = {
            .id = p->src_id
    };
    ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
    if (b == NULL) {
        bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
    }
    //发送
    bridge_send(b, ops_packet_forward_data_remote, packet->service_id, packet->stream_id, packet->data, size);
}
static void forward_data_local(ops_bridge* bridge, ops_packet* packet, int size) {
    ops_forward ths = {
               .id = packet->service_id
    };
    ops_forward* p = RB_FIND(_ops_forward_tree, &bridge->global->forward, &ths);
    if (p == NULL) {
        bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
    }
    //查找目标客户端是否存在
    ops_bridge ths_b = {
            .id = p->dst_id
    };
    ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &ths_b);
    if (b == NULL) {
        bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
    }
    //发送
    bridge_send(b, ops_packet_forward_data_local, packet->service_id, packet->stream_id, packet->data, size);
}
#endif
//----------------------------------------------------------------------------------------------------------------------vpc
static void vpc_data(ops_bridge* bridge, ops_packet* packet, int size) {
    uint8_t* data = packet->data;
    uint8_t ip_version = packet->data[0] >> 4;
    ops_bridge the = { 0 };
    uint32_t mid = 0;
    switch (ip_version)
    {
    case 4: {
        ops_route_v4 v4 = { 0 };
        memcpy(&v4.ip, &data[16], sizeof(v4.ip));
        ops_route_v4* r = RB_FIND(_ops_route_v4_tree, &bridge->global->route_v4, &v4);
        if (!r) {
            return;
        }
        the.id = r->id;
        mid = r->mid;
        break;
    }
    case 6: {
        ops_route_v6 v6 = { 0 };
        memcpy(&v6.ip, &data[24], sizeof(v6.ip));
        ops_route_v6* r = RB_FIND(_ops_route_v6_tree, &bridge->global->route_v6, &v6);
        if (!r) {
            return;
        }
        the.id = r->id;
        mid = r->mid;
        break;
    }
    default:
        return;
    }
    //查找客户端
    ops_bridge* b = RB_FIND(_ops_bridge_tree, &bridge->global->bridge, &the);
    if (!b) {
        return;
    }
    //转发
    bridge_send(b, ops_packet_vpc_data, packet->service_id, mid, packet->data, size);
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
    if (count > 0) {
        bridge_send(bridge, ops_packet_forward, 0, 0, pack, sdslen(pack));
    }
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
    if (count > 0) {
        bridge_send(bridge, ops_packet_host, 0, 0, pack, sdslen(pack));
    }
    sdsfree(pack);
    //查询相关的vpc节点
    pack = sdsnewlen(NULL, 4);//预留数量
    count = 0;
    ops_members* mc = NULL;
    RB_FOREACH(mc, _ops_members_tree, &bridge->global->members) {
        if (mc->bid == bridge->id) {
            ops_member mem;
            mem.id = htonl(mc->id);
            mem.vid = htons(mc->vpc->id);
            memcpy(mem.ipv4, mc->ipv4, sizeof(mem.ipv4));
            memcpy(mem.ipv6, mc->ipv6, sizeof(mem.ipv6));
            memcpy(&buf, &mem, sizeof(mem));
            pack = sdscatlen(pack, buf, sizeof(mem));
            count++;
        }
    }
    *(uint32_t*)pack = htonl(count);
    //下发主机服务
    if (count > 0) {
        bridge_send(bridge, ops_packet_vpc, 0, 0, pack, sdslen(pack));
    }
    sdsfree(pack);

    //更新统计
    bridge->global->stat.bridge_online++;
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
        ops_key _key = {
            .key = packet->data + 2
        };
        ops_key* key = RB_FIND(_ops_key_tree, &bridge->global->key, &_key);
        if (key == NULL) {
            bridge_send(bridge, ops_packet_auth, 0, 0, NULL, 0);
        }
        else {
            ops_bridge ths = {
                .id = key->id
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
                bridge->id = key->id;
                RB_INSERT(_ops_bridge_tree, &bridge->global->bridge, bridge);
                bridge_auth_ok(bridge);
            }
        }
        break;
    }
    case ops_packet_ping: {
        uint64_t t = *(uint64_t*)&packet->data[0];
        bridge->ping = ntohl(*(uint32_t*)&packet->data[8]);
        bridge_send(bridge, ops_packet_ping, 0, 0, packet->data, 8);
        break;
    }
    case ops_packet_forward_ctl: {//转发控制指令
        forward_ctl(bridge, packet, size);
        break;
    }
    case ops_packet_forward_data_remote: {//远程来的转发数据
        //查找服务
        forward_data_remote(bridge, packet, size);
        break;
    }
    case ops_packet_forward_data_local: {//本地来的转发数据
        //查找服务
        forward_data_local(bridge, packet, size);
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
    case ops_packet_vpc_data: {
        vpc_data(bridge, packet, size);
        break;
    }
    default:
        break;
    }
}
//关闭
static void bridge_close_cb(uv_handle_t* handle) {
    ops_bridge* bridge = (ops_bridge*)handle->data;
    //通知对端服务
    ops_forward* fc = NULL;
    RB_FOREACH(fc, _ops_forward_tree, &bridge->global->forward) {
        //来源
        if (fc->src_id == bridge->id) {

        }
        //出口
        if (fc->dst_id == bridge->id) {

        }
    }
    //从句柄树中移除
    RB_REMOVE(_ops_bridge_tree, &bridge->global->bridge, bridge);
    bridge->global->stat.bridge_online--;
    //回收资源
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
static void on_data_key_add(ops_global* global, uint16_t id, const char* k) {
    ops_key* key = malloc(sizeof(*key));
    if (key == NULL)
        return;
    memset(key, 0, sizeof(*key));
    key->id = id;
    key->key = strdup(k);
    RB_INSERT(_ops_key_tree, &global->key, key);
    global->stat.bridge_count++;
}
static void on_data_key_del(ops_global* global, const char* k) {
    ops_key _key = {
           .key = k
    };
    ops_key* key = RB_FIND(_ops_key_tree, &global->key, &_key);
    if (key == NULL) {
        return;
    }
    free(key->key);
    //踢出相关客户端

    RB_REMOVE(_ops_key_tree, &global->key, key);
    free(key);
    global->stat.bridge_count--;
}
//通道发生改变
static void on_data_forward_add(ops_global* global, uint32_t id, uint16_t src_id, uint16_t dst_id, uint8_t type, uint16_t src_port, const char* bind, const char* dst, uint16_t dst_port) {
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
static void on_data_forward_del(ops_global* global, uint32_t id) {
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
    free(forward);
}
//
static void on_data_host_add(ops_global* global, uint32_t id, const char* src_host, uint16_t dst_id, uint8_t type, const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite) {
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
static void on_data_host_del(ops_global* global, const char* h) {
    ops_host _host = {
           .host = h
    };
    ops_host* host = RB_FIND(_ops_host_tree, &global->host, &_host);
    if (host == NULL) {
        return;
    }
    free(host->host);
    if (host->host_rewrite) {
        free(host->host_rewrite);
    }
    //通知相关客户端当前服务已移除



    RB_REMOVE(_ops_host_tree, &global->host, host);
    free(host);
}
//
static void on_data_vpc_add(ops_global* global, uint16_t id, const char* ipv4, const char* ipv6) {
    ops_vpc* vpc = malloc(sizeof(*vpc));
    if (vpc == NULL)
        return;
    memset(vpc, 0, sizeof(*vpc));
    vpc->id = id;
    struct sockaddr_in addr;
    uv_ip4_addr(ipv4, 0, &addr);
    memcpy(&vpc->ipv4, &addr.sin_addr, sizeof(vpc->ipv4));
    struct sockaddr_in6 addr6;
    uv_ip6_addr(ipv6, 0, &addr6);
    memcpy(&vpc->ipv6, &addr6.sin6_addr, sizeof(vpc->ipv6));
    RB_INSERT(_ops_vpc_tree, &global->vpc, vpc);
}
//
static void on_data_member_add(ops_global* global, uint32_t id, uint16_t bid, uint16_t vid, const char* ipv4, const char* ipv6) {
    //查找vpc
    ops_vpc the = {
        .id = vid
    };
    ops_vpc* v = RB_FIND(_ops_vpc_tree, &global->vpc, &the);
    if (!v) {
        //没有对应的vpc
        return;
    }
    //
    ops_members* mem = malloc(sizeof(*mem));
    if (mem == NULL)
        return;
    memset(mem, 0, sizeof(*mem));
    mem->id = id;
    mem->bid = bid;
    mem->vpc = v;
    struct sockaddr_in addr;
    uv_ip4_addr(ipv4, 0, &addr);
    memcpy(&mem->ipv4, &addr.sin_addr, sizeof(mem->ipv4));
    struct sockaddr_in6 addr6;
    uv_ip6_addr(ipv6, 0, &addr6);
    memcpy(&mem->ipv6, &addr6.sin6_addr, sizeof(mem->ipv6));
    RB_INSERT(_ops_members_tree, &global->members, mem);
    //生成路由
    ops_route_v4* v4 = (ops_route_v4*)malloc(sizeof(*v4));
    if (!v4) {
        return;
    }
    memset(v4, 0, sizeof(*v4));
    v4->id = bid;
    v4->mid = id;
    memcpy(&v4->ip, &addr.sin_addr, sizeof(v4->ip));
    RB_INSERT(_ops_route_v4_tree, &global->route_v4, v4);
    ops_route_v4* v6 = (ops_route_v6*)malloc(sizeof(*v6));
    if (!v6) {
        return;
    }
    memset(v6, 0, sizeof(*v6));
    v6->id = bid;
    v6->mid = id;
    memcpy(&v6->ip, &addr6.sin6_addr, sizeof(v6->ip));
    RB_INSERT(_ops_route_v6_tree, &global->route_v6, v6);
}
struct data_settings data_settings = { on_data_key_add, on_data_key_del, on_data_forward_add, on_data_forward_del, on_data_host_add ,on_data_host_del, on_data_vpc_add, on_data_member_add };
//----------------------------------------------------------------------------------------------------------------------
//全局初始化
static int init_global(ops_global* global) {
    struct sockaddr_in _addr;
    //初始化数据
    data_init(global->config.db_file, global, &data_settings);
    //web管理
    global->listen.web.tcp.data = global;
    uv_tcp_init(loop, &global->listen.web.tcp);
    uv_ip4_addr("0.0.0.0", global->config.web_port, &_addr);
    uv_tcp_bind(&global->listen.web.tcp, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.web.tcp, DEFAULT_BACKLOG, web_connection_cb);

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
    global->listen.https.tcp.data = global;
    uv_tcp_init(loop, &global->listen.https.tcp);
    uv_ip4_addr("0.0.0.0", global->config.https_proxy_port, &_addr);
    uv_tcp_bind(&global->listen.https.tcp, &_addr, 0);
    uv_listen((uv_stream_t*)&global->listen.https.tcp, DEFAULT_BACKLOG, https_connection_cb);
}
//加载配置
static load_config(ops_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.db_file = "data.db";
    global->config.bridge_port = 1664;
    global->config.web_port = 8088;
    global->config.https_proxy_port = 443;
    global->config.http_proxy_port = 80;
    global->config.admin_user = "admin";
    global->config.admin_pass = "1234";

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

