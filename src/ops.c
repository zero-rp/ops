#include <uv.h>
#include <cJSON.h>
#include <databuffer.h>
#include <common.h>

#define DEFAULT_BACKLOG 128
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
    uv_tcp_t web;                      //web界面
    uv_tcp_t bridge;                   //客户端
    uv_tcp_t https;                     //
    uv_tcp_t http;                      //
    struct messagepool m_mp;            //接收缓冲
    ops_config config;
    //服务列表

}ops_global;
//客户端
typedef struct _ops_bridge {
    ops_global* global;
    uv_tcp_t tcp;               //连接
    struct databuffer m_buffer; //接收缓冲
    uint16_t id;                //客户端ID
}ops_bridge;
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



//
static void bridge_on_data(ops_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
    switch (packet->type)
    {
    case ops_packet_auth: {
        //读取key长度
        uint16_t key_len = ntohs(*(uint16_t*)(&packet->data));
        break;
    }
    default:
        break;
    }


}



//重载服务
static service_reload(ops_global* global) {
    //加载文件








}


//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}


static void http_connection_cb(uv_stream_t* tcp, int status) {

}

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
        return;
    }
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &global->m_mp, buf, nread);
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
    memset(bridge, 0, sizeof(bridge));
    bridge->global = global;

    uv_tcp_init(loop, &bridge->tcp);//初始化tcp bridge句柄
    bridge->tcp.data = bridge;

    if (uv_accept(tcp, (uv_stream_t*)&bridge->tcp) == 0) {
        //新客户
        uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);
    }
}

//启动服务端
static int init_global(ops_global* global) {
    struct sockaddr_in _addr;

    //web管理
    global->web.data = global;
    uv_tcp_init(loop, &global->web);
    uv_ip4_addr("0.0.0.0", global->config.web_port, &_addr);
    uv_tcp_bind(&global->web, &_addr, 0);
    uv_listen((uv_stream_t*)&global->web, DEFAULT_BACKLOG, bridge_connection_cb);

    //客户端桥接
    global->bridge.data = global;
    uv_tcp_init(loop, &global->bridge);
    uv_ip4_addr("0.0.0.0", global->config.bridge_port, &_addr);
    uv_tcp_bind(&global->bridge, &_addr, 0);
    uv_listen((uv_stream_t*)&global->bridge, DEFAULT_BACKLOG, bridge_connection_cb);

    //http端口
    global->http.data = global;
    uv_tcp_init(loop, &global->http);
    uv_ip4_addr("0.0.0.0", global->config.http_proxy_port, &_addr);
    uv_tcp_bind(&global->http, &_addr, 0);
    uv_listen((uv_stream_t*)&global->http, DEFAULT_BACKLOG, http_connection_cb);

    //https端口
    global->https.data = global;
    uv_tcp_init(loop, &global->https);
    uv_ip4_addr("0.0.0.0", global->config.https_proxy_port, &_addr);
    uv_tcp_bind(&global->https, &_addr, 0);
    uv_listen((uv_stream_t*)&global->https, DEFAULT_BACKLOG, http_connection_cb);

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
    //初始化服务
    init_global(global);
    //刷新配置
    service_reload(global);



    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

