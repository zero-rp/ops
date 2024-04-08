#include <uv.h>
#include <cJSON.h>
#include <uv/tree.h>
#include "databuffer.h"
#include "common.h"

#define DEFAULT_BACKLOG 128

//转发隧道来源
typedef struct _opc_forward_tunnel_src {
    RB_ENTRY(_opc_forward_tunnel_src) entry;    //
    uint32_t stream_id;                         //流ID
    uint32_t pree_id;                           //对端流ID
    uv_tcp_t tcp;                               //
    struct _opc_forward_src* src;
}opc_forward_tunnel_src;
RB_HEAD(_opc_forward_tunnel_src_tree_s, _opc_forward_tunnel_src);
//转发隧道目标
typedef struct _opc_forward_tunnel_dst {
    RB_ENTRY(_opc_forward_tunnel_dst) entry;    //
    uint32_t stream_id;                         //流ID
    uint32_t pree_id;                           //对端流ID
    uv_tcp_t tcp;                               //
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
    uint16_t port;
    char dst[256];                      //目标
    struct _opc_bridge* bridge;
}opc_forward_dst;
RB_HEAD(_opc_forward_dst_tree_s, _opc_forward_dst);
//主机隧道目标
typedef struct _opc_host_tunnel {
    RB_ENTRY(_opc_host_tunnel) entry;    //
    uint32_t stream_id;                         //流ID
    uint32_t pree_id;                           //对端流ID
    uv_tcp_t tcp;                               //
    uv_connect_t req;
    uv_getaddrinfo_t req_info;
    struct _opc_host* dst;
}opc_host_tunnel;
RB_HEAD(_opc_host_tunnel_tree_s, _opc_host_tunnel);
//主机
typedef struct _opc_host {
    RB_ENTRY(_opc_host) entry;    //
    uint32_t id;                        //转发服务ID
    uv_tcp_t tcp;                       //监听
    uint16_t port;
    char dst[256];                      //目标
    struct _opc_bridge* bridge;
}opc_host;
RB_HEAD(_opc_host_tree_s, _opc_host);

//
typedef struct _opc_bridge {
    uv_tcp_t tcp;                                       //服务器通讯句柄
    struct _opc_global* global;
    struct databuffer m_buffer;                         //接收缓冲
    uint32_t forward_tunnel_id;                         //转发流ID分配
    struct _opc_forward_tunnel_src_tree_s tunnel_src;
    struct _opc_forward_tunnel_dst_tree_s tunnel_dst;   //
    struct _opc_forward_dst_tree_s forward_dst;
    uint32_t host_tunnel_id;                         //转发流ID分配
    struct _opc_host_tunnel_tree_s host_tunnel;
    struct _opc_host_tree_s host;
}opc_bridge;
//配置
typedef struct _opc_config {
    const char* auth_key;       //web api密钥
    const char* server_ip;      //服务器IP
    uint16_t server_port;       //服务器端口
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
static int _opc_host_compare(opc_host* w1, opc_host* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_host_tree_s, _opc_host, entry, _opc_host_compare)
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
static int _opc_host_tunnel_compare(opc_host_tunnel* w1, opc_host_tunnel* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_host_tunnel_tree_s, _opc_host_tunnel, entry, _opc_host_tunnel_compare)
//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}

static void bridge_send(opc_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
//--------------------------------------------------------------------------------------------------------forward
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
    //转发
    bridge_send(tunnel->src->bridge, ops_packet_forward_data_local, tunnel->src->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//转发连接进入
static void forward_connection_cb(uv_stream_t* tcp, int status) {
    opc_forward_src* src = (opc_forward_src*)tcp->data;
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
    if (!tunnel)
        return;
    memset(tunnel, 0, sizeof(*tunnel));

    uv_tcp_init(loop, &tunnel->tcp);//初始化tcp bridge句柄
    tunnel->tcp.data = tunnel;

    if (uv_accept(tcp, (uv_stream_t*)&tunnel->tcp) == 0) {
        //记录
        tunnel->src = src;
        tunnel->stream_id = src->bridge->forward_tunnel_id++;
        RB_INSERT(_opc_forward_tunnel_src_tree_s, &src->bridge->tunnel_src, tunnel);
        //日志
        printf("New Forward\r\n");

        //打开转发隧道
        uint8_t buf[1];
        buf[0] = 0x01;//发起请求
        bridge_send(src->bridge, ops_packet_forward_ctl, src->id, tunnel->stream_id, buf, sizeof(buf));
    }
}

//转发隧道目标数据到达
static void forward_tunnel_dst_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_forward_tunnel_dst* tunnel = (opc_forward_tunnel_dst*)tcp->data;
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
    //转发
    bridge_send(tunnel->dst->bridge, ops_packet_forward_data_remote, tunnel->dst->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//连接返回
static void forward_connect_cb(uv_connect_t* req, int status) {
    opc_forward_tunnel_dst* tunnel = req->data;
    if (status < 0) {
        //连接失败
        return;
    }
    //通知成功
    uint8_t buf[5];
    buf[0] = 0x02;//连接成功
    *(uint32_t*)(&buf[1]) = htonl(tunnel->stream_id);
    bridge_send(tunnel->dst->bridge, ops_packet_forward_ctl, tunnel->dst->id, tunnel->pree_id, buf, sizeof(buf));
    //连接远端成功
    uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_dst_read_cb);
}
//转发隧道解析目标主机
static void forward_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_forward_tunnel_dst* tunnel = req->data;
    if (status != 0) {

        return;
    }
    tunnel->tcp.data = tunnel;
    tunnel->req.data = tunnel;
    uv_tcp_init(loop, &tunnel->tcp);
    uv_tcp_connect(&tunnel->req, &tunnel->tcp, res->ai_addr, forward_connect_cb);
}
//--------------------------------------------------------------------------------------------------------host
//转发隧道目标数据到达
static void host_tunnel_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_host_tunnel* tunnel = (opc_host_tunnel*)tcp->data;
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
    //转发
    bridge_send(tunnel->dst->bridge, ops_packet_host_data, tunnel->dst->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//连接返回
static void host_connect_cb(uv_connect_t* req, int status) {
    opc_host_tunnel* tunnel = req->data;
    if (status < 0) {
        //连接失败
        return;
    }
    //通知成功
    uint8_t buf[5];
    buf[0] = 0x01;//连接成功
    *(uint32_t*)(&buf[1]) = htonl(tunnel->stream_id);
    bridge_send(tunnel->dst->bridge, ops_packet_host_ctl, tunnel->dst->id, tunnel->pree_id, buf, sizeof(buf));
    //连接远端成功
    uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, host_tunnel_read_cb);
}
//HOST隧道解析目标主机
static void host_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_host_tunnel* tunnel = req->data;
    if (status != 0) {

        return;
    }
    tunnel->tcp.data = tunnel;
    tunnel->req.data = tunnel;
    uv_tcp_init(loop, &tunnel->tcp);
    uv_tcp_connect(&tunnel->req, &tunnel->tcp, res->ai_addr, host_connect_cb);
}

//--------------------------------------------------------------------------------------------------------bridge
//成功连接上服务器
static void bridge_connect_end(opc_bridge* bridge) {
    //发送鉴权数据
    int size = strlen(bridge->global->config.auth_key) + 3;
    char* buf = malloc(size);
    if (buf == NULL)
        return;
    *(uint16_t*)(buf) = htons(size - 2);
    strcpy(buf + 2, bridge->global->config.auth_key);
    bridge_send(bridge, ops_packet_auth, 0, 0, buf, size);
    free(buf);
}
//收到服务端来的数据
static void bridge_on_data(opc_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
    packet->service_id = ntohl(packet->service_id);
    packet->stream_id = ntohl(packet->stream_id);
    size -= sizeof(ops_packet);
    switch (packet->type)
    {
    case ops_packet_auth: {//鉴权数据
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
    case ops_packet_forward: {//下发转发服务
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
                dst.port = ntohs(dst.port);

                opc_forward_dst* d = (opc_forward_dst*)malloc(sizeof(*d));
                memset(d, 0, sizeof(*d));
                d->id = dst.sid;
                d->bridge = bridge;
                memcpy(d->dst, dst.dst, sizeof(d->dst));
                d->dst[sizeof(d->dst) - 1] = 0;
                d->port = dst.port;

                RB_INSERT(_opc_forward_dst_tree_s, &bridge->forward_dst, d);
            }
            else {

            }
        }



        break;
    }
    case ops_packet_forward_ctl: {//转发控制指令
        uint8_t type = packet->data[0];
        switch (type)
        {
        case 0x01: {//发起请求
            //查找目标服务
            opc_forward_dst ths = {
                   .id = packet->service_id
            };
            opc_forward_dst* dst = RB_FIND(_opc_forward_dst_tree_s, &bridge->forward_dst, &ths);
            if (dst == NULL) {
                bridge_send(bridge, ops_packet_forward_ctl, packet->service_id, packet->stream_id, NULL, 0);
                break;
            }
            //请求连接远端
            opc_forward_tunnel_dst* tunnel = (opc_forward_tunnel_dst*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
            if (!tunnel)
                return;
            memset(tunnel, 0, sizeof(*tunnel));
            tunnel->dst = dst;
            tunnel->stream_id = bridge->forward_tunnel_id++;
            tunnel->pree_id = packet->stream_id;
            RB_INSERT(_opc_forward_tunnel_dst_tree_s, &bridge->tunnel_dst, tunnel);
            //开始连接,解析主机
            tunnel->req_info.data = tunnel;
            char buf[10] = { 0 };
            snprintf(buf, sizeof(buf), "%d", dst->port);
            uv_getaddrinfo(loop, &tunnel->req_info, forward_getaddrinfo_cb, dst->dst, buf, NULL);
            break;
        }
        case 0x02: {//连接成功
            opc_forward_tunnel_src the = {
                .stream_id = packet->stream_id
            };
            opc_forward_tunnel_src* tunnel = RB_FIND(_opc_forward_tunnel_src_tree_s, &bridge->tunnel_src, &the);
            if (!tunnel)
                break;
            //读取对端流ID
            tunnel->pree_id = ntohl(*(uint32_t*)(&packet->data[1]));
            //开始接收本地数据
            uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_src_read_cb);

            break;
        }
        default:
            break;
        }
        break;
    }
    case ops_packet_forward_data_local: {//本地来的转发数据
        opc_forward_tunnel_dst  the = {
                .stream_id = packet->stream_id
        };
        opc_forward_tunnel_dst* tunnel = RB_FIND(_opc_forward_tunnel_dst_tree_s, &bridge->tunnel_dst, &the);
        if (!tunnel)
            break;
        //转发数据到远程
        uv_buf_t buf[] = { 0 };
        buf->len = size;
        buf->base = malloc(size);
        if (buf->base == NULL) {
            break;
        }
        memcpy(buf->base, packet->data, size);
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        if (req == NULL) {
            free(buf->base);
            return;
        }
        req->data = buf->base;
        uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
        break;
    }
    case ops_packet_forward_data_remote: {//远程来的转发数据
        opc_forward_tunnel_src  the = {
                .stream_id = packet->stream_id
        };
        opc_forward_tunnel_src* tunnel = RB_FIND(_opc_forward_tunnel_src_tree_s, &bridge->tunnel_src, &the);
        if (!tunnel)
            break;
        //转发数据到本地
        uv_buf_t buf[] = { 0 };
        buf->len = size;
        buf->base = malloc(size);
        if (buf->base == NULL) {
            break;
        }
        memcpy(buf->base, packet->data, size);
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        if (req == NULL) {
            free(buf->base);
            return;
        }
        req->data = buf->base;
        uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
        break;
    }
    case ops_packet_host: {
        int count = ntohl(*(uint32_t*)&packet->data[0]);
        char* pos = &packet->data[4];
        for (size_t i = 0; i < count; i++) {
            ops_host_dst dst;
            memcpy(&dst, pos, sizeof(dst));
            pos += sizeof(dst);
            dst.sid = ntohl(dst.sid);
            dst.port = ntohs(dst.port);

            opc_host* d = (opc_host*)malloc(sizeof(*d));
            memset(d, 0, sizeof(*d));
            d->id = dst.sid;
            d->bridge = bridge;
            memcpy(d->dst, dst.dst, sizeof(d->dst));
            d->dst[sizeof(d->dst) - 1] = 0;
            d->port = dst.port;

            RB_INSERT(_opc_host_tree_s, &bridge->host, d);
        }
        break;
    }
    case ops_packet_host_ctl: {//域名控制服务
        opc_host ths = {
            .id = packet->service_id
        };
        opc_host* dst = RB_FIND(_opc_host_tree_s, &bridge->host, &ths);
        if (dst == NULL) {
            bridge_send(bridge, ops_packet_host_ctl, packet->service_id, packet->stream_id, NULL, 0);
            break;
        }
        //请求连接远端
        opc_host_tunnel* tunnel = (opc_host_tunnel*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
        if (!tunnel)
            return;
        memset(tunnel, 0, sizeof(*tunnel));
        tunnel->dst = dst;
        tunnel->stream_id = bridge->host_tunnel_id++;
        tunnel->pree_id = packet->stream_id;
        RB_INSERT(_opc_host_tunnel_tree_s, &bridge->host_tunnel, tunnel);
        //开始连接,解析主机
        tunnel->req_info.data = tunnel;
        char buf[10] = { 0 };
        snprintf(buf, sizeof(buf), "%d", dst->port);
        uv_getaddrinfo(loop, &tunnel->req_info, host_getaddrinfo_cb, dst->dst, buf, NULL);
        break;
    }
    case ops_packet_host_data: {
        opc_host_tunnel  the = {
            .stream_id = packet->stream_id
        };
        opc_host_tunnel* tunnel = RB_FIND(_opc_host_tunnel_tree_s, &bridge->host_tunnel, &the);
        if (!tunnel)
            break;
        //转发数据到远程
        uv_buf_t buf[] = { 0 };
        buf->len = size;
        buf->base = malloc(size);
        if (buf->base == NULL) {
            break;
        }
        memcpy(buf->base, packet->data, size);
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        if (req == NULL) {
            free(buf->base);
            return;
        }
        req->data = buf->base;
        uv_write(req, &tunnel->tcp, &buf, 1, write_cb);

        break;
    }
    default:
        break;
    }
}



//向服务器发送数据
static void bridge_send(opc_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len) {
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
        printf("Server Disconnected\r\n");
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
            return;
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
static void bridge_connect_cb(uv_connect_t* req, int status) {
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
//--------------------------------------------------------------------------------------------------------
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
    uv_ip4_addr(global->config.server_ip, global->config.server_port, &_addr);
    uv_tcp_connect(req, &bridge->tcp, &_addr, bridge_connect_cb);
}
//全局初始化
static int init_global(opc_global* global) {
    uv_timer_init(loop, &global->re_timer);
    global->re_timer.data = global;

}
//加载配置
static load_config(opc_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.server_ip = "127.0.0.1";
    global->config.server_port = 1664;

    //从命令行加载参数
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            i++;
            global->config.server_ip = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-p") == 0) {
            i++;
            global->config.server_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-a") == 0) {
            i++;
            global->config.auth_key = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-c") == 0) {

        }
        else if (strcmp(argv[i], "-i") == 0) {
            char* buf = malloc(500);
            scanf("%s", buf);
            global->config.auth_key = buf;
        }
    }
}

int main(int argc, char* argv[]) {
    loop = uv_default_loop();
    opc_global* global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //加载参数
    load_config(global, argc, argv);
    //初始化
    init_global(global);
    //开始连接
    start_connect(global);

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
