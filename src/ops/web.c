#include <time.h>
#include <uv.h>
#include <uv/tree.h>
#include <openssl/rand.h>
#include <common/sds.h>
#include <llhttp.h>
#include <cJSON.h>
#include "web.h"
#include "data.h"

//web授权信息
typedef struct _ops_auth {
    RB_ENTRY(_ops_auth) entry;          //
    char token[65];                     //
    time_t time;                        //时间
}ops_auth;
RB_HEAD(_ops_auth_tree, _ops_auth);
//web管理连接,只使用http1
typedef struct _web_conn {
    ops_web* web;
    uv_tcp_t tcp;                               //连接
    llhttp_t parser;                            //解析器
    sds url;                                    //请求地址
    sds body;                                   //请求数据
}web_conn;
//
typedef struct _ops_web {
    ops_global* global;
    uv_tcp_t tcp;
    struct _ops_auth_tree auth;
}web_web;

static int _ops_auth_compare(ops_auth* w1, ops_auth* w2) {
    return strcmp(w1->token, w2->token);
}
RB_GENERATE_STATIC(_ops_auth_tree, _ops_auth, entry, _ops_auth_compare)


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

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
//发送回调
static void web_write_cb(uv_write_t* req, int status) {
    sdsfree(req->data);
}
//发送原始数据
static int web_respose_raw(web_conn* conn, sds data) {
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
    return uv_write(req, &conn->tcp, &buf, 1, web_write_cb);
}
//
static void web_respose_html(web_conn* conn, const char* html, int len) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: text/html;charset=utf-8;\r\n"
        "\r\n",
        200, "OK", len);
    //数据
    data = sdscatlen(data, html, len);
    web_respose_raw(conn, data);
}
//
static void web_respose_chunked_header(web_conn* conn) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Transfer-Encoding:chunked\r\n"
        //"Content-Type: text/html;charset=utf-8;\r\n"
        "\r\n",
        200, "OK");
    web_respose_raw(conn, data);
}
static void web_respose_chunked_data(web_conn* conn, char* buf, int len) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "%zx\r\n", len);
    if (buf && len) {
        data = sdscatlen(data, buf, len);
    }
    data = sdscat(data, "\r\n");
    web_respose_raw(conn, data);
}
//跨域处理
static void web_respose_cors(web_conn* conn) {
    //生成应答头
    sds data = sdscatprintf(sdsempty(),
        "HTTP/1.1 %d %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Access-Control-Allow- Methods: POST\r\n"
        "Access-Control-Max-Age: 1728000\r\n"
        "\r\n",
        204, "OK");
    web_respose_raw(conn, data);
}
//web管理应答
static void web_respose_json(web_conn* conn, int code, const char* msg, cJSON* json) {
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
    web_respose_raw(conn, data);
}


struct web_read {
    uv_buf_t buf;
    uv_file file;
    web_conn* web;
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
        uv_fs_close(req->loop, &close_req, wr->file, NULL);
    }
    //读取到数据
    else if (req->result > 0) {
        //发送数据块
        web_respose_chunked_data(wr->web, wr->buf.base, req->result);
        //继续读取
        uv_fs_read(req->loop, req, wr->file, &wr->buf, 1, -1, web_on_read);
    }
}
//
void web_fs_cb(uv_fs_t* req) {
    web_conn* web = req->data;
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
        uv_fs_read(req->loop, read_req, req->result, &wr->buf, 1, -1, web_on_read);
    }
    else {
        //打开文件失败

    }
    uv_fs_req_cleanup(req);
    free(req);
}
//
void web_respose_file(web_conn* conn, const char* file) {
    uv_fs_t* req = (uv_fs_t*)malloc(sizeof(*req));
    if (!req) {
        web_respose_html(conn, "404", 3);
        return;
    }
    req->data = conn;
    char path[512] = { 0 };
    snprintf(path, sizeof(path), "%s/%s", "./web", file);
    if (uv_fs_open(ops_get_loop(conn->web->global), req, path, 0, 0, web_fs_cb) != 0) {
        web_respose_html(conn, "404", 3);
    }
}
//web管理请求
static void web_on_request(web_conn* conn, cJSON* body) {
    if (conn->parser.method == HTTP_OPTIONS) {
        return web_respose_cors(conn);
    }
    cJSON* data = cJSON_CreateObject();
    char* url = conn->url;
    if (url[0] != '/')
        goto err;
    switch (url[1])
    {
    case 0x00: {
        return web_respose_file(conn, "index.html");
    }
    case 'l': {
        url++;
        if (strcmp(url, "layui/css/layui.css") == 0 || strcmp(url, "layui/layui.js") == 0 || strcmp(url, "layui/font/iconfont.woff2") == 0) {
            return web_respose_file(conn, url);
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
        return web_respose_json(conn, -2, "NO BODY", data);
    }
    // 登录
    if (url[0] == 'a' && url[1] == 'u' && url[2] == 't' && url[3] == 'h') {
        cJSON* user = cJSON_GetObjectItem(body, "user");
        cJSON* pass = cJSON_GetObjectItem(body, "pass");
        if (!user || !pass || !user->valuestring || !pass->valuestring) {
            return web_respose_json(conn, -3, "user or pass is null", data);
        }
        if (strcmp(user->valuestring, opc_get_config(conn->web->global)->admin_user) != 0 || strcmp(pass->valuestring, opc_get_config(conn->web->global)->admin_pass) != 0) {
            return web_respose_json(conn, -4, "user or pass is error", data);
        }
        //生成token
        char buf[16];
        RAND_bytes(buf, 16);
        //记录TOKEN
        ops_auth* auth = (ops_auth*)malloc(sizeof(*auth));
        memset(auth, 0, sizeof(*auth));
        hex2str(buf, 16, auth->token);
        auth->time = time(NULL);
        RB_INSERT(_ops_auth_tree, &conn->web->auth, auth);
        cJSON_AddStringToObject(data, "token", auth->token);
        goto ok;
    }
    //鉴权
    cJSON* token = cJSON_GetObjectItem(body, "token");
    if (!token || !token->valuestring) {
        return web_respose_json(conn, 403, "NO AUTH", data);
    }
    ops_auth _auth = { 0 };
    strncpy(_auth.token, token->valuestring, 32);
    ops_auth* auth = RB_FIND(_ops_auth_tree, &conn->web->auth, &_auth);
    if (!auth || (time(NULL) - auth->time) > 60 * 30) {
        return web_respose_json(conn, 403, "NO AUTH", data);
    }
    auth->time = time(NULL);
    //服务器信息
    if (strcmp(url, "info") == 0) {
        cJSON* config = cJSON_AddObjectToObject(data, "config");
        cJSON_AddNumberToObject(config, "web_port", opc_get_config(conn->web->global)->web_port);
        cJSON_AddNumberToObject(config, "http_port", opc_get_config(conn->web->global)->http_proxy_port);
        cJSON_AddNumberToObject(config, "https_port", opc_get_config(conn->web->global)->https_proxy_port);
        cJSON* stat = cJSON_AddObjectToObject(data, "stat");
        cJSON_AddNumberToObject(stat, "bridge_count", 0);//web->global->stat.bridge_count);
        cJSON_AddNumberToObject(stat, "bridge_online", 0);//web->global->stat.bridge_online);
        goto ok;
    }
    //客户列表
    else if (strcmp(url, "bridge") == 0) {
        cJSON* list = data_bridge_get();
        int num = cJSON_GetArraySize(list);
        //获取在线设备
        for (size_t i = 0; i < num; i++) {
            cJSON* item = cJSON_GetArrayItem(list, i);
            cJSON* id = cJSON_GetObjectItem(item, "id");
            if (!id || !id->valuestring) {
                continue;
            }
            /*
            ops_bridge* b = bridge_find(, atoi(id->valuestring));
            if (b) {
                cJSON_AddBoolToObject(item, "online", 1);
                cJSON_AddNumberToObject(item, "ping", b->ping);
                char ip[INET6_ADDRSTRLEN] = { 0 };
                uv_ip_name(&b->peer, ip, INET6_ADDRSTRLEN);
                cJSON_AddStringToObject(item, "peer", ip);
                ip[0] = 0;
                uv_ip_name(&b->local, ip, INET6_ADDRSTRLEN);
                cJSON_AddStringToObject(item, "local", ip);
            }
            */
        }
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
            return web_respose_json(conn, -1, "add error", data);
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
            return web_respose_json(conn, -1, "del error", data);
        }
    }
    //生成新key
    else if (strcmp(url, "bridge_new_key") == 0) {
        //生成key
        char buf[16];
        char key[33];
        RAND_bytes(buf, 16);
        hex2str(buf, 16, key);
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        //记录数据
        if (data_bridge_new_key(id->valueint, key) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(conn, -1, "update error", data);
        }
    }
    //转发列表
    else if (strcmp(url, "forward") == 0) {
        cJSON* list = data_forward_get();
        cJSON_AddItemToObject(data, "list", list);

        goto ok;
    }
    //添加转发
    else if (strcmp(url, "forward_add") == 0 || strcmp(url, "forward_update") == 0) {
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
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (id && id->valueint) {
            if (data_forward_update(id->valueint, src_id->valueint, dst_id->valueint, type->valueint, src_port->valueint, bind ? bind->valuestring : "", dst->valuestring, dst_port->valueint, info ? info->valuestring : "") == 0) {
                goto ok;
            }
            else {
                return web_respose_json(conn, -1, "update error", data);
            }
        }
        else {
            if (data_forward_add(src_id->valueint, dst_id->valueint, type->valueint, src_port->valueint, bind ? bind->valuestring : "", dst->valuestring, dst_port->valueint, info ? info->valuestring : "") == 0) {
                goto ok;
            }
            else {
                return web_respose_json(conn, -1, "add error", data);
            }
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
            return web_respose_json(conn, -1, "del error", data);
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
            return web_respose_json(conn, -1, "add error", data);
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
            return web_respose_json(conn, -1, "del error", data);
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
            return web_respose_json(conn, -1, "add error", data);
        }
    }
    //删除网络
    else if (strcmp(url, "vpc_del") == 0) {
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        if (data_vpc_del(id->valueint) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(conn, -1, "del error", data);
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
            return web_respose_json(conn, -1, "add error", data);
        }
    }
    //删除成员
    else if (strcmp(url, "member_del") == 0) {
        cJSON* id = cJSON_GetObjectItem(body, "id");
        if (!id) {
            goto err_data;
        }
        if (id->valueint == 0) {
            goto err_data;
        }
        if (data_member_del(id->valueint) == 0) {
            goto ok;
        }
        else {
            return web_respose_json(conn, -1, "del error", data);
        }
    }
ok:
    return web_respose_json(conn, 0, "ok", data);
err_data:
    return web_respose_json(conn, -1, "data error", data);
err://未识别的地址
    return web_respose_json(conn, 404, "NO URL", data);
}
//HTTP应答解析回调
//消息完毕
static int web_on_message_complete(llhttp_t* p) {
    web_conn* conn = (web_conn*)p->data;
    cJSON* body = NULL;
    if (conn->body) {
        body = cJSON_ParseWithLength(conn->body, sdslen(conn->body));
    }
    web_on_request(conn, body);
    cJSON_free(body);
    //重置请求
    if (conn->url) {
        sdsfree(conn->url);
        conn->url = NULL;
    }
    if (conn->body) {
        sdsfree(conn->body);
        conn->body = NULL;
    }
    return 0;
}
//解析到消息体
static int web_on_body(llhttp_t* p, const char* buf, size_t len) {
    web_conn* conn = (web_conn*)p->data;
    if (conn->body == NULL) {
        conn->body = sdsnewlen(buf, len);
    }
    else {
        conn->body = sdscatlen(conn->body, buf, len);
    }
    return 0;
}
//解析到域名
static int web_on_url(llhttp_t* p, const char* buf, size_t len) {
    web_conn* conn = (web_conn*)p->data;
    if (conn->url == NULL) {
        conn->url = sdsnewlen(buf, len);
    }
    else {
        conn->url = sdscatlen(conn->url, buf, len);
    }
    return 0;
}
static llhttp_settings_t web_parser_settings = { 
    NULL,
    web_on_url,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    web_on_body,
    web_on_message_complete,
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
    NULL };
//连接关闭
static void web_close_cb(uv_handle_t* handle) {
    web_conn* web = (web_conn*)handle->data;
    if (web->url) {
        sdsfree(web->url);
    }
    if (web->body) {
        sdsfree(web->body);
    }
    free(web);
}
static void web_shutdown_cb(uv_shutdown_t* req, int status) {
    web_conn* conn = (web_conn*)req->data;
    uv_close(&conn->tcp, web_close_cb);
    free(req);
}
//读取到数据
static void web_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    web_conn* conn = (web_conn*)tcp->data;
    ops_web* web = conn->web;
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
                req->data = conn;
                uv_shutdown(req, tcp, web_shutdown_cb);
            }
            else {
                //分配内存失败,直接强制关闭
                uv_close(tcp, web_close_cb);
            }
        }
        return;
    }
    llhttp_execute(&conn->parser, buf->base, nread);
    free(buf->base);
}
static void web_connection_cb(uv_stream_t* tcp, int status) {
    ops_web* web = (ops_web*)tcp->data;
    web_conn* conn = (web_conn*)malloc(sizeof(web_conn));//为tcp bridge申请资源
    if (!conn)
        return;
    memset(conn, 0, sizeof(*conn));
    conn->web = web;

    uv_tcp_init(ops_get_loop(web->global), &conn->tcp);//初始化tcp bridge句柄
    conn->tcp.data = conn;

    if (uv_accept(tcp, (uv_stream_t*)&conn->tcp) == 0) {
        llhttp_init(&conn->parser, HTTP_REQUEST, &web_parser_settings);//初始化解析器
        conn->parser.data = conn;

        uv_read_start((uv_stream_t*)&conn->tcp, alloc_buffer, web_read_cb);
    }
}
//创建模块
ops_web* web_new(ops_global* global) {
    ops_web* web = (ops_web*)malloc(sizeof(ops_web));
    if (!web)
        return NULL;
    memset(web, 0, sizeof(*web));
    web->global = global;

    web->tcp.data = web;
    uv_tcp_init(ops_get_loop(global), &web->tcp);
    struct sockaddr_in6 addr;
    uv_ip6_addr("::0", opc_get_config(global)->web_port, &addr);
    uv_tcp_bind(&web->tcp, &addr, 0);
    uv_listen((uv_stream_t*)&web->tcp, 32, web_connection_cb);
    return web;
}