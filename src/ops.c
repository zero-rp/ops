#include <uv.h>
#include <cJSON.h>
#include <http_parser.h>
#include <uv/tree.h>
#include "databuffer.h"
#include "common.h"
#include "data.h"
#include "sds.h"

#define DEFAULT_BACKLOG 128
//转发服务
typedef struct _ops_forward {
    RB_ENTRY(_ops_forward) entry;       //
    uint32_t id;                        //转发服务ID
    uint16_t src_id;                    //来源客户ID
    uint16_t dst_id;                    //目标客户ID
    ops_forward_dst dst;                //目标信息
    ops_forward_src src;                //来源信息
}ops_forward;
RB_HEAD(_ops_forward_tree_s, _ops_forward);
//客户端
typedef struct _ops_bridge {
    RB_ENTRY(_ops_bridge) entry;        //
    uint16_t id;                        //客户端ID
    struct _ops_global* global;
    uv_tcp_t tcp;                       //连接
    struct databuffer m_buffer;         //接收缓冲
}ops_bridge;
RB_HEAD(_ops_bridge_tree_s, _ops_bridge);
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
}ops_config;
//
typedef struct _ops_global {
    struct {
        uv_tcp_t web;                       //web界面
        uv_tcp_t bridge;                    //客户端
        uv_tcp_t https;                     //
        uv_tcp_t http;                      //
    }listen;                            //
    struct messagepool m_mp;            //接收缓冲
    ops_config config;
    //服务列表
    struct _ops_forward_tree_s forward; //转发器
    struct _ops_bridge_tree_s bridge;   //客户端
}ops_global;
//web管理连接
typedef struct _ops_web {
    ops_global* global;
    uv_tcp_t tcp;               //连接
    struct http_parser parser;  //解析器
    sds path;
}ops_web;
//HTTP连接
typedef struct _ops_http {
    ops_global* global;
    uv_tcp_t tcp;               //连接
    struct http_parser parser;  //解析器
}ops_http;
//服务类型
enum ops_service_type
{
    ops_service_http = 1,
    ops_service_https,
    ops_service_socks,
};
//服务定义
typedef struct _ops_service {
    enum ops_service_type type; //服务类型
    uint16_t bridge_id;         //关联的客户端ID


}ops_service;


static uv_loop_t* loop = NULL;

static int _ops_forward_compare(ops_forward* w1, ops_forward* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_forward_tree_s, _ops_forward, entry, _ops_forward_compare)
static int _ops_bridge_compare(ops_bridge* w1, ops_bridge* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_bridge_tree_s, _ops_bridge, entry, _ops_bridge_compare)

//添加转发器
static void add_forward(ops_global* global, uint32_t id, uint16_t src_id, uint16_t dst_id, uint8_t type, uint16_t src_port, const char* dst, uint16_t dst_port) {
    ops_forward ths = {
        .id = id
    };
    //查找ID是否存在
    ops_forward* forward = RB_FIND(_ops_forward_tree_s, &global->forward, &ths);
    if (forward == NULL) {
        forward = malloc(sizeof(*forward));
        if (forward == NULL)
            return;
        memset(forward, 0, sizeof(*forward));
        forward->id = id;
        RB_INSERT(_ops_forward_tree_s, &global->forward, forward);
    }
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
}
//


//重载服务
static service_reload(ops_global* global) {
    //
    add_forward(global, 1, 1, 2, 1, 1088, "www.baidu.com", 80);







}


//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
//发送回调
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
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
//HTTP应答解析回调
//消息完毕
static int http_on_message_complete(http_parser* p) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//解析到消息体
static int http_on_body(http_parser* p, const char* buf, size_t len) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//解析到头V
static int http_on_header_value(http_parser* p, const char* buf, size_t len) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//解析到头K
static int http_on_header_field(http_parser* p, const char* buf, size_t len) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
//头部解析完毕
static int http_on_headers_complete(http_parser* p) {

    return 0;
}
//解析开始
static int http_on_message_begin(http_parser* p) {
    struct ops_http* http = (struct ops_http*)p->data;

    return 0;
}
static http_parser_settings parser_settings = { http_on_message_begin, NULL, NULL, http_on_header_field, http_on_header_value, http_on_headers_complete, http_on_body, http_on_message_complete, NULL, NULL };
//读取到数据
static void http_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_http* http = (ops_http*)tcp->data;
    ops_global* global = http->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        return;
    }
    http_parser_execute(&http->parser, &parser_settings, buf->base, nread);
    free(buf->base);
}
//http连接进入
static void http_connection_cb(uv_stream_t* tcp, int status) {
    ops_global* global = (ops_global*)tcp->data;
    ops_http* http = (ops_http*)malloc(sizeof(ops_http));//为tcp bridge申请资源
    if (!http)
        return;
    memset(http, 0, sizeof(*http));
    http->global = global;

    http_parser_init(&http->parser, HTTP_REQUEST);//初始化解析器
    http->parser.data = http;

    uv_tcp_init(loop, &http->tcp);//初始化tcp bridge句柄
    http->tcp.data = http;

    if (uv_accept(tcp, (uv_stream_t*)&http->tcp) == 0) {
        uv_read_start((uv_stream_t*)&http->tcp, alloc_buffer, http_read_cb);
    }
}
//----------------------------------------------------------------------------------------------------------------------客户端处理
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
    char buf[1 + sizeof(ops_forward_dst) + sizeof(ops_forward_src)];
    int count = 0;
    //查询客户端转发服务
    ops_forward* tc = NULL;
    RB_FOREACH(tc, _ops_forward_tree_s, &bridge->global->forward) {
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
        uint16_t client_id = data_find_auth_key(packet->data + 2, key_len);
        if (client_id == 0) {
            bridge_send(bridge, ops_packet_auth, 0, 0, NULL, 0);
        }
        else {
            ops_forward ths = {
                .id = client_id
            };
            //查找ID是否存在
            ops_bridge* p = RB_FIND(_ops_bridge_tree_s, &bridge->global->bridge, &ths);
            if (p != NULL) {
                bridge_send(bridge, ops_packet_auth,0, 0, NULL, 0);
            }
            else {
                char buf[1];
                buf[0] = 1;//鉴权成功
                bridge_send(bridge, ops_packet_auth,0, 0, buf, 1);
                //记录客户端
                bridge->id = client_id;
                RB_INSERT(_ops_bridge_tree_s, &bridge->global->bridge, bridge);
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
        ops_forward* p = RB_FIND(_ops_forward_tree_s, &bridge->global->forward, &ths);
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
            ops_bridge* b = RB_FIND(_ops_bridge_tree_s, &bridge->global->bridge, &ths_b);
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
            ops_bridge* b = RB_FIND(_ops_bridge_tree_s, &bridge->global->bridge, &ths_b);
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
        ops_forward* p = RB_FIND(_ops_forward_tree_s, &bridge->global->forward, &ths);
        if (p == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //查找来源客户端是否存在
        ops_bridge ths_b = {
                .id = p->src_id
        };
        ops_bridge* b = RB_FIND(_ops_bridge_tree_s, &bridge->global->bridge, &ths_b);
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
        ops_forward* p = RB_FIND(_ops_forward_tree_s, &bridge->global->forward, &ths);
        if (p == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //查找目标客户端是否存在
        ops_bridge ths_b = {
                .id = p->dst_id
        };
        ops_bridge* b = RB_FIND(_ops_bridge_tree_s, &bridge->global->bridge, &ths_b);
        if (b == NULL) {
            bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //发送
        bridge_send(b, ops_packet_forward_data_local, packet->service_id, packet->stream_id, packet->data, size);
        break;
    }
    default:
        break;
    }


}
//读取到数据
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_bridge* bridge = (ops_bridge*)tcp->data;
    ops_global* global = bridge->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        //
        if (bridge->id) {
            RB_REMOVE(_ops_bridge_tree_s, &bridge->global->bridge, bridge);
        }
        return;
    }
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &global->m_mp, buf->base, nread);
    for (;;) {
        int size = databuffer_readheader(&bridge->m_buffer, &global->m_mp, 4);
        if (size < 0) {
            return 0;
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
//----------------------------------------------------------------------------------------------------------------------
//全局初始化
static int init_global(ops_global* global) {
    struct sockaddr_in _addr;

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
static load_config(ops_global* global) {
    global->config.bridge_port = 1664;
    global->config.web_port = 8088;
    global->config.https_proxy_port = 443;
    global->config.http_proxy_port = 80;

}

int main() {
    loop = uv_default_loop();
    //启动监听
    ops_global* global = (ops_global*)malloc(sizeof(*global));
    if (global == NULL)
        return;
    memset(global, 0, sizeof(*global));
    //加载参数
    load_config(global);
    //初始化
    init_global(global);
    //刷新配置
    service_reload(global);



    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

