#include <uv.h>
#include <cJSON.h>
#include <uv/tree.h>
#include "databuffer.h"
#include "common.h"

#define DEFAULT_BACKLOG 128

//转发隧道来源
typedef struct _opc_forward_tunnel_src {
    RB_ENTRY(_opc_forward_tunnel_src) entry;    //
    uint32_t stream_id;                     //流ID
    uint32_t id;                            //转发服务ID
    uv_tcp_t tcp;                           //
    struct _opc_forward_src* src;
}opc_forward_tunnel_src;
RB_HEAD(_opc_forward_tunnel_src_tree_s, _opc_forward_tunnel_src);
//转发隧道目标
typedef struct _opc_forward_tunnel_dst {
    RB_ENTRY(_opc_forward_tunnel_dst) entry;    //
    uint32_t stream_id;                     //流ID
    uint32_t id;                            //转发服务ID
    uv_tcp_t tcp;                           //
    uv_connect_t req;
    uv_getaddrinfo_t req_info;
    struct _opc_forward_dst* dst;
}opc_forward_tunnel_dst;
RB_HEAD(_opc_forward_tunnel_dst_tree_s, _opc_forward_tunnel_dst);
//转发器
typedef struct _opc_forward_src {
    RB_ENTRY(_opc_forward_src) entry;    //
    uint32_t id;                        //转发服务ID
    uv_tcp_t tcp;                       //监听
    struct _opc_bridge* bridge;
}opc_forward_src;
typedef struct _opc_forward_dst {
    RB_ENTRY(_opc_forward_dst) entry;    //
    uint32_t id;                        //转发服务ID
    uv_tcp_t tcp;                       //监听
    char dst[256];                      //目标
    struct _opc_bridge* bridge;
}opc_forward_dst;
RB_HEAD(_opc_forward_dst_tree_s, _opc_forward_dst);
//
typedef struct _opc_bridge {
    uv_tcp_t tcp;                                       //服务器通讯句柄
    struct _opc_global* global;
    struct databuffer m_buffer;                         //接收缓冲
    uint32_t forward_tunnel_id;                         //转发流ID分配
    struct _opc_forward_tunnel_src_tree_s tunnel_src;
    struct _opc_forward_tunnel_dst_tree_s tunnel_dst;   //
    struct _opc_forward_dst_tree_s forward_dst;
}opc_bridge;
//配置
typedef struct _opc_config {
    const char* auth_key;       //web api密钥
}opc_config;
//
typedef struct _opc_global {
    uv_tcp_t tcp;                       //连接
    struct messagepool m_mp;            //接收缓冲
    uv_timer_t re_timer;                //重连定时器
    struct _opc_bridge* bridge;
    opc_config config;                  //
}opc_global;


static uv_loop_t* loop = NULL;


static int _opc_forward_dst_compare(opc_forward_dst* w1, opc_forward_dst* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_dst_tree_s, _opc_forward_dst, entry, _opc_forward_dst_compare)
static int _opc_forward_tunnel_src_compare(opc_forward_tunnel_src* w1, opc_forward_tunnel_src* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_src_tree_s, _opc_forward_tunnel_src, entry, _opc_forward_tunnel_src_compare)
static int _opc_forward_tunnel_dst_compare(opc_forward_tunnel_dst* w1, opc_forward_tunnel_dst* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_dst_tree_s, _opc_forward_tunnel_dst, entry, _opc_forward_tunnel_dst_compare)

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}

static void bridge_send(opc_bridge* bridge, uint8_t  type, uint32_t stream_id, const char* data, uint32_t len);

//转发隧道来源数据到达
static void forward_tunnel_src_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        //回收资源

        return;
    }

}
//转发连接进入
static void forward_connection_cb(uv_stream_t* tcp, int status) {
    opc_forward_src* src = (opc_forward_src*)tcp->data;
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
    if (!tunnel)
        return;
    memset(tunnel, 0, sizeof(*tunnel));
    tunnel->src = src;
    tunnel->stream_id = src->bridge->forward_tunnel_id++;
    RB_INSERT(_opc_forward_tunnel_src_tree_s, &src->bridge->tunnel_src, tunnel);

    //打开转发隧道
    char buf[4];
    *(uint32_t*)buf = htonl(src->id);
    bridge_send(src->bridge, ops_packet_forward_open, tunnel->stream_id, buf, sizeof(buf));


    uv_tcp_init(loop, &tunnel->tcp);//初始化tcp bridge句柄
    tunnel->tcp.data = tunnel;

    if (uv_accept(tcp, (uv_stream_t*)&tunnel->tcp) == 0) {
        //新转发
        uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_src_read_cb);
    }
}
//转发隧道解析目标主机
static void forward_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_forward_tunnel_dst* tunnel = req->data;
    if (status != 0) {

        return;
    }
    uv_tcp_init(loop, &tunnel->tcp);
    uv_tcp_connect(&tunnel->req, &tunnel->tcp, res->ai_addr, bridge_connect);
}


//成功连接上服务器
static void bridge_connect_end(opc_bridge* bridge) {
    //发送鉴权数据
    int size = strlen(bridge->global->config.auth_key) + 2;
    char* buf = malloc(size);
    if (buf == NULL)
        return;
    *(uint16_t*)(buf) = htons(size - 2);
    memcpy(buf + 2, bridge->global->config.auth_key, size - 2);
    bridge_send(bridge, ops_packet_auth, 0, buf, size);
    free(buf);
}
//收到服务端来的数据
static void bridge_on_data(opc_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
    size -= sizeof(ops_packet);
    switch (packet->type)
    {
    case ops_packet_auth: {
        if (size == 1 && packet->data[0] == 0x01) {
            printf("Auth Ok!\r\n");
        }
        else {
            printf("Auth Err!\r\n");
        }
        break;
    }
    case ops_packet_ping: {
        break;
    }
    case ops_packet_forward: {
        //读取数量
        int count = ntohl(*(uint32_t*)&packet->data[0]);
        char* pos = &packet->data[4];
        for (size_t i = 0; i < count; i++) {
            //读取类型
            uint8_t type = pos[0];
            pos++;
            if (type == 1) {//转发源
                ops_forward_src src;
                memcpy(&src, pos, sizeof(src));
                pos += sizeof(src);
                src.sid = ntohl(src.sid);
                src.port = ntohs(src.port);

                opc_forward_src* s = (opc_forward_src*)malloc(sizeof(*s));
                memset(s, 0, sizeof(*s));
                s->id = src.sid;
                s->bridge = bridge;


                struct sockaddr_in _addr;
                uv_tcp_init(loop, &s->tcp);
                s->tcp.data = s;
                uv_ip4_addr("0.0.0.0", src.port, &_addr);
                uv_tcp_bind(&s->tcp, &_addr, 0);
                uv_listen((uv_stream_t*)&s->tcp, DEFAULT_BACKLOG, forward_connection_cb);
            }
            else if (type == 2) {//转发目标
                ops_forward_dst dst;
                memcpy(&dst, pos, sizeof(dst));
                pos += sizeof(dst);
                dst.sid = ntohl(dst.sid);

                opc_forward_dst* d = (opc_forward_dst*)malloc(sizeof(*d));
                memset(d, 0, sizeof(*d));
                d->id = dst.sid;
                d->bridge = bridge;
                memcpy(d->dst, dst.dst, sizeof(d->dst));
                d->dst[sizeof(d->dst) - 1] = 0;
                
                RB_INSERT(_opc_forward_dst_tree_s, &bridge->forward_dst, d);
            }
            else {

            }
        }



        break;
    }
    case ops_packet_forward_open: {
        //打开远端失败
        if (size == 0) {



            break;
        }
        //读取服务ID
        int id = ntohl(*(uint32_t*)&packet->data[0]);
        //查找目标服务
        opc_forward_dst ths = {
               .id = id
        };
        opc_forward_dst* dst = RB_FIND(_opc_forward_dst_tree_s, &bridge->forward_dst, &ths);
        if (dst == NULL) {
            bridge_send(bridge, ops_packet_forward_open, packet->stream_id, NULL, 0);
            break;
        }

        //请求连接远端
        opc_forward_tunnel_dst* tunnel = (opc_forward_tunnel_dst*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
        if (!tunnel)
            return;
        memset(tunnel, 0, sizeof(*tunnel));
        tunnel->dst = dst;
        tunnel->stream_id = bridge->forward_tunnel_id++;
        RB_INSERT(_opc_forward_tunnel_dst_tree_s, &bridge->tunnel_dst, tunnel);
        //开始连接,解析主机
        tunnel->tcp.data = tunnel;
        tunnel->req.data = tunnel;
        tunnel->req_info.data = tunnel;
        uv_getaddrinfo(loop, &tunnel->req_info, forward_getaddrinfo_cb, dst->dst, NULL, NULL);
        break;
    }
    default:
        break;
    }
}



//向服务器发送数据
static void bridge_send(opc_bridge* bridge, uint8_t  type, uint32_t stream_id, const char* data, uint32_t len) {
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + len;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = type;
    pack->stream_id = stream_id;
    memcpy(pack->data, data, len);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &bridge->tcp, &buf, 1, write_cb);
}
//数据到达
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_bridge* bridge = (opc_bridge*)tcp->data;
    opc_global* global = bridge->global;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        //回收资源

        global->bridge = NULL;
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
//重连回调
static int start_connect(opc_global* global);
void bridge_re_timer_cb(uv_timer_t* handle) {
    start_connect((opc_global*)handle->data);
}
//连接返回
static void bridge_connect(uv_connect_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    free(req);
    if (status < 0) {
        //定时重连
        uv_timer_start(&bridge->global->re_timer, bridge_re_timer_cb, 1000 * 5, 0);
        //释放资源
        free(bridge);
        return;
    }
    //连接成功
    bridge->global->bridge = bridge;
    //
    uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);
    //
    bridge_connect_end(bridge);
}
//启动连接
static int start_connect(opc_global* global) {
    opc_bridge* bridge = (opc_bridge*)malloc(sizeof(*bridge));
    if (bridge == NULL)
        return 0;
    memset(bridge, 0, sizeof(*bridge));
    bridge->global = global;
    uv_connect_t* req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    if (req == NULL) {
        free(req);
        return 0;
    }
    memset(req, 0, sizeof(uv_connect_t));

    uv_tcp_init(loop, &bridge->tcp);
    bridge->tcp.data = bridge;
    req->data = bridge;
    struct sockaddr_in _addr;
    uv_ip4_addr("127.0.0.1", 1664, &_addr);
    uv_tcp_connect(req, &bridge->tcp, &_addr, bridge_connect);
}
//全局初始化
static int init_global(opc_global* global) {
    uv_timer_init(loop, &global->re_timer);
    global->re_timer.data = global;

}
//加载配置
static load_config(opc_global* global) {
    char* buf = malloc(500);
    scanf("%s", buf);
    global->config.auth_key = buf;

}

int main() {
    loop = uv_default_loop();
    opc_global* global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //加载参数
    load_config(global);
    //初始化
    init_global(global);
    //开始连接
    start_connect(global);

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
