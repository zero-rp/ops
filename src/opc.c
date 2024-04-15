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
RB_HEAD(_opc_forward_tunnel_src_tree, _opc_forward_tunnel_src);
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
RB_HEAD(_opc_forward_tunnel_dst_tree, _opc_forward_tunnel_dst);
//转发器
typedef struct _opc_forward_src {
    RB_ENTRY(_opc_forward_src) entry;    //
    uint32_t id;                        //转发服务ID
    uv_tcp_t tcp;                       //监听
    struct _opc_bridge* bridge;
}opc_forward_src;
RB_HEAD(_opc_forward_src_tree, _opc_forward_src);
typedef struct _opc_forward_dst {
    RB_ENTRY(_opc_forward_dst) entry;    //
    uint32_t id;                        //转发服务ID
    char bind[256];                     //绑定本地地址
    char dst[256];                      //目标
    uint16_t port;                      //目标端口
    struct _opc_bridge* bridge;
}opc_forward_dst;
RB_HEAD(_opc_forward_dst_tree, _opc_forward_dst);
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
RB_HEAD(_opc_host_tunnel_tree, _opc_host_tunnel);
//主机
typedef struct _opc_host {
    RB_ENTRY(_opc_host) entry;    //
    uint32_t id;                        //转发服务ID
    uv_tcp_t tcp;                       //监听
    uint16_t port;
    char bind[256];                     //
    char dst[256];                      //目标
    struct _opc_bridge* bridge;
}opc_host;
RB_HEAD(_opc_host_tree, _opc_host);
//VPC
typedef struct _opc_vpc {
    RB_ENTRY(_opc_vpc) entry;    //
    uint32_t id;                            //成员id
    uint16_t vid;                           //
    uint8_t ipv4[4];                        //ipv4地址
    uint8_t ipv6[16];                       //ipv6地址
    void* data;                 //接口数据
    struct _opc_bridge* bridge;
}opc_vpc;
RB_HEAD(_opc_vpc_tree, _opc_vpc);
//
typedef struct _opc_bridge {
    uv_tcp_t tcp;                                       //服务器通讯句柄
    struct _opc_global* global;
    struct databuffer m_buffer;                         //接收缓冲
    uv_timer_t keep_timer;                              //心跳定时器
    uint64_t keep_last;                                 //上次心跳
    uint32_t keep_ping;                                 //延迟
    uint32_t forward_tunnel_id;                         //转发流ID分配
    struct _opc_forward_tunnel_src_tree tunnel_src;     //
    struct _opc_forward_tunnel_dst_tree tunnel_dst;     //
    struct _opc_forward_dst_tree forward_dst;
    uint32_t host_tunnel_id;                            //主机流ID分配
    struct _opc_host_tunnel_tree host_tunnel;           //主机隧道
    struct _opc_host_tree host;
    struct _opc_vpc_tree vpc;
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

static int _opc_forward_src_compare(opc_forward_src* w1, opc_forward_src* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_src_tree, _opc_forward_src, entry, _opc_forward_src_compare)
static int _opc_forward_dst_compare(opc_forward_dst* w1, opc_forward_dst* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_dst_tree, _opc_forward_dst, entry, _opc_forward_dst_compare)
static int _opc_host_compare(opc_host* w1, opc_host* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_host_tree, _opc_host, entry, _opc_host_compare)
static int _opc_vpc_compare(opc_vpc* w1, opc_vpc* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_vpc_tree, _opc_vpc, entry, _opc_vpc_compare)
static int _opc_forward_tunnel_src_compare(opc_forward_tunnel_src* w1, opc_forward_tunnel_src* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_src_tree, _opc_forward_tunnel_src, entry, _opc_forward_tunnel_src_compare)
static int _opc_forward_tunnel_dst_compare(opc_forward_tunnel_dst* w1, opc_forward_tunnel_dst* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_dst_tree, _opc_forward_tunnel_dst, entry, _opc_forward_tunnel_dst_compare)
static int _opc_host_tunnel_compare(opc_host_tunnel* w1, opc_host_tunnel* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_host_tunnel_tree, _opc_host_tunnel, entry, _opc_host_tunnel_compare)
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
//-----------------------------------------------------来源
//来源连接关闭
static void forward_src_close_cb(uv_handle_t* handle) {
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)handle->data;


    RB_REMOVE(_opc_forward_tunnel_src_tree, &tunnel->src->bridge->tunnel_src, tunnel);
    free(tunnel);
}
static void forward_src_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_forward_tunnel_src* conn = (opc_forward_tunnel_src*)req->data;
    uv_close(&conn->tcp, forward_src_close_cb);
    free(req);
}
static void forward_src_shutdown(opc_forward_tunnel_src* tunnel) {
    uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
    if (req != NULL) {
        memset(req, 0, sizeof(*req));
        req->data = tunnel;
        uv_shutdown(req, &tunnel->tcp, forward_src_shutdown_cb);
    }
    else {
        //分配内存失败,直接强制关闭
        uv_close(&tunnel->tcp, forward_src_close_cb);
    }
}
//转发隧道来源数据到达
static void forward_tunnel_src_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, forward_src_close_cb);
        }
        else {
            //shutdown
            forward_src_shutdown(tunnel);
        }
        return;
    }
    //转发
    bridge_send(tunnel->src->bridge, ops_packet_forward_data_local, tunnel->src->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//转发连接进入
static void forward_src_connection_cb(uv_stream_t* tcp, int status) {
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
        RB_INSERT(_opc_forward_tunnel_src_tree, &src->bridge->tunnel_src, tunnel);
        //日志
        printf("New Forward\r\n");

        //打开转发隧道
        uint8_t buf[1];
        buf[0] = 0x01;//发起请求
        bridge_send(src->bridge, ops_packet_forward_ctl, src->id, tunnel->stream_id, buf, sizeof(buf));
    }
}
//-----------------------------------------------------目标
//失败关闭对端隧道
static void forward_dst_err(opc_bridge* bridge, uint32_t service_id, uint32_t stream_id) {
    uint8_t buf[2];
    buf[0] = 0x02;//来自目标的应答
    buf[1] = 0x01;//连接失败
    bridge_send(bridge, ops_packet_forward_ctl, service_id, stream_id, buf, sizeof(buf));
}
//来源连接关闭
static void forward_dst_close_cb(uv_handle_t* handle) {
    opc_forward_tunnel_src* tunnel = (opc_forward_tunnel_src*)handle->data;


    free(tunnel);
}
static void forward_dst_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_forward_tunnel_src* conn = (opc_forward_tunnel_src*)req->data;
    uv_close(&conn->tcp, forward_dst_close_cb);
    free(req);
}
static void forward_dst_shutdown(opc_forward_tunnel_dst* tunnel) {
    uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
    if (req != NULL) {
        memset(req, 0, sizeof(*req));
        req->data = tunnel;
        uv_shutdown(req, &tunnel->tcp, forward_dst_shutdown_cb);
    }
    else {
        //分配内存失败,直接强制关闭
        uv_close(&tunnel->tcp, forward_dst_close_cb);
    }
}
//转发隧道目标数据到达
static void forward_tunnel_dst_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_forward_tunnel_dst* tunnel = (opc_forward_tunnel_dst*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, forward_dst_close_cb);
        }
        else {
            //shutdown
            forward_dst_shutdown(tunnel);
        }
        return;
    }
    //转发
    bridge_send(tunnel->dst->bridge, ops_packet_forward_data_remote, tunnel->dst->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//连接返回
static void forward_dst_connect_cb(uv_connect_t* req, int status) {
    opc_forward_tunnel_dst* tunnel = req->data;
    if (status < 0) {
        //连接失败
        forward_dst_err(tunnel->dst->bridge, tunnel->dst->id, tunnel->pree_id);
        return;
    }
    //通知成功
    uint8_t buf[6];
    buf[0] = 0x02;//来自目标的应答
    buf[1] = 0x02;//连接成功
    *(uint32_t*)(&buf[2]) = htonl(tunnel->stream_id);
    bridge_send(tunnel->dst->bridge, ops_packet_forward_ctl, tunnel->dst->id, tunnel->pree_id, buf, sizeof(buf));
    //连接远端成功
    uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_dst_read_cb);
}
//转发隧道解析目标主机
static void forward_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_forward_tunnel_dst* tunnel = req->data;
    if (status != 0) {
        //通知失败
        forward_dst_err(tunnel->dst->bridge, tunnel->dst->id, tunnel->pree_id);
        return;
    }
    tunnel->tcp.data = tunnel;
    tunnel->req.data = tunnel;
    uv_tcp_init(loop, &tunnel->tcp);
    //绑定本地地址
    if (strlen(tunnel->dst->bind) > 0) {
        //uv_tcp_bind(&tunnel->req, , 0);
    }
    uv_tcp_connect(&tunnel->req, &tunnel->tcp, res->ai_addr, forward_dst_connect_cb);
    //释放结果
    uv_freeaddrinfo(res);
}
//服务器控制回调
static void forward(opc_bridge* bridge, ops_packet* packet) {
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
            if (!s) {
                continue;
            }
            memset(s, 0, sizeof(*s));
            s->id = src.sid;
            s->bridge = bridge;

            //监听端口
            struct sockaddr_in _addr;
            uv_tcp_init(loop, &s->tcp);
            s->tcp.data = s;
            uv_ip4_addr("0.0.0.0", src.port, &_addr);
            uv_tcp_bind(&s->tcp, &_addr, 0);
            uv_listen((uv_stream_t*)&s->tcp, DEFAULT_BACKLOG, forward_src_connection_cb);
        }
        else if (type == 2) {//转发目标
            ops_forward_dst dst;
            memcpy(&dst, pos, sizeof(dst));
            pos += sizeof(dst);
            dst.sid = ntohl(dst.sid);
            dst.port = ntohs(dst.port);

            opc_forward_dst* d = (opc_forward_dst*)malloc(sizeof(*d));
            if (!d) {
                continue;
            }
            memset(d, 0, sizeof(*d));
            d->id = dst.sid;
            d->bridge = bridge;
            memcpy(d->dst, dst.dst, sizeof(d->dst));
            d->dst[sizeof(d->dst) - 1] = 0;
            d->port = dst.port;

            RB_INSERT(_opc_forward_dst_tree, &bridge->forward_dst, d);
        }
        else {

        }
    }
}
static void forward_ctl(opc_bridge* bridge, ops_packet* packet) {
    uint8_t type = packet->data[0];
    switch (type)
    {
    case 0x01: {//发起请求
        //查找目标服务
        opc_forward_dst ths = {
               .id = packet->service_id
        };
        opc_forward_dst* dst = RB_FIND(_opc_forward_dst_tree, &bridge->forward_dst, &ths);
        if (dst == NULL) {
            forward_dst_err(bridge, packet->service_id, packet->stream_id);
            break;
        }
        //请求连接远端
        opc_forward_tunnel_dst* tunnel = (opc_forward_tunnel_dst*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
        if (!tunnel) {
            forward_dst_err(bridge, packet->service_id, packet->stream_id);
            break;
        }
        memset(tunnel, 0, sizeof(*tunnel));
        tunnel->dst = dst;
        tunnel->stream_id = bridge->forward_tunnel_id++;
        tunnel->pree_id = packet->stream_id;
        RB_INSERT(_opc_forward_tunnel_dst_tree, &bridge->tunnel_dst, tunnel);
        //开始连接,解析主机
        tunnel->req_info.data = tunnel;
        char buf[10] = { 0 };
        snprintf(buf, sizeof(buf), "%d", dst->port);
        uv_getaddrinfo(loop, &tunnel->req_info, forward_getaddrinfo_cb, dst->dst, buf, NULL);
        break;
    }
    case 0x02: {//来自目标的应答
        opc_forward_tunnel_src the = {
            .stream_id = packet->stream_id
        };
        opc_forward_tunnel_src* tunnel = RB_FIND(_opc_forward_tunnel_src_tree, &bridge->tunnel_src, &the);
        if (!tunnel) {
            //连接已经不存在了,丢弃
            break;
        }
        if (packet->data[1] == 0x01) {
            //失败或异常,将本地连接关闭
            forward_src_shutdown(tunnel);
        }
        else if (packet->data[1] == 0x02) {
            //成功
            //读取对端流ID
            tunnel->pree_id = ntohl(*(uint32_t*)(&packet->data[2]));
            //开始接收本地数据
            uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_src_read_cb);
        }
        break;
    }
    case 0x03: {//来自来源的应答
        opc_forward_tunnel_dst the = {
            .stream_id = packet->stream_id
        };
        opc_forward_tunnel_dst* tunnel = RB_FIND(_opc_forward_tunnel_dst_tree, &bridge->tunnel_dst, &the);
        if (!tunnel) {
            //连接已经不存在了,丢弃
            break;
        }
        if (packet->data[1] == 0x01) {
            //来源异常
            forward_dst_shutdown(tunnel);
        }
        break;
    }
    default:
        break;
    }
}
static void forward_data_local(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_forward_tunnel_dst  the = {
                .stream_id = packet->stream_id
    };
    opc_forward_tunnel_dst* tunnel = RB_FIND(_opc_forward_tunnel_dst_tree, &bridge->tunnel_dst, &the);
    if (!tunnel)
        return;
    //转发数据到远程
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(size);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, packet->data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
}
static void forward_data_remote(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_forward_tunnel_src  the = {
                .stream_id = packet->stream_id
    };
    opc_forward_tunnel_src* tunnel = RB_FIND(_opc_forward_tunnel_src_tree, &bridge->tunnel_src, &the);
    if (!tunnel)
        return;
    //转发数据到本地
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(size);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, packet->data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
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
        //解析失败
        return;
    }
    tunnel->tcp.data = tunnel;
    tunnel->req.data = tunnel;
    uv_tcp_init(loop, &tunnel->tcp);
    //绑定本地地址
    if (strlen(tunnel->dst->bind) > 0) {
        //uv_tcp_bind(&tunnel->req, , 0);
    }
    uv_tcp_connect(&tunnel->req, &tunnel->tcp, res->ai_addr, host_connect_cb);
    //释放结果
    uv_freeaddrinfo(res);
}

static void host(opc_bridge* bridge, ops_packet* packet) {
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

        RB_INSERT(_opc_host_tree, &bridge->host, d);
    }
}
static void host_ctl(opc_bridge* bridge, ops_packet* packet) {
    opc_host ths = {
    .id = packet->service_id
    };
    opc_host* dst = RB_FIND(_opc_host_tree, &bridge->host, &ths);
    if (dst == NULL) {
        bridge_send(bridge, ops_packet_host_ctl, packet->service_id, packet->stream_id, NULL, 0);
        return;
    }
    //请求连接远端
    opc_host_tunnel* tunnel = (opc_host_tunnel*)malloc(sizeof(*tunnel));//为tcp tunnel申请资源
    if (!tunnel)
        return;
    memset(tunnel, 0, sizeof(*tunnel));
    tunnel->dst = dst;
    tunnel->stream_id = bridge->host_tunnel_id++;
    tunnel->pree_id = packet->stream_id;
    RB_INSERT(_opc_host_tunnel_tree, &bridge->host_tunnel, tunnel);
    //开始连接,解析主机
    tunnel->req_info.data = tunnel;
    char buf[10] = { 0 };
    snprintf(buf, sizeof(buf), "%d", dst->port);
    uv_getaddrinfo(loop, &tunnel->req_info, host_getaddrinfo_cb, dst->dst, buf, NULL);
}
static void host_data(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_host_tunnel  the = {
    .stream_id = packet->stream_id
    };
    opc_host_tunnel* tunnel = RB_FIND(_opc_host_tunnel_tree, &bridge->host_tunnel, &the);
    if (!tunnel)
        return;
    //转发数据到远程
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(size);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, packet->data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
}
//--------------------------------------------------------------------------------------------------------vpc
static vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size);
//ip数据过滤

#ifdef _WIN32
#include <wintun.h>
#include <iphlpapi.h>

static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

static HMODULE InitializeWintun(void) {
    HMODULE Wintun =
        LoadLibrary(L"wintun.dll");
    if (!Wintun)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

typedef void* QUEUE[2];

typedef struct _win_tun_packet {
    QUEUE wq;                    //队列
    int size;
    uint8_t data[0];
}win_tun_packet;

typedef struct _win_tun {
    HMODULE mod;                    //动态库
    WINTUN_ADAPTER_HANDLE Adapter;  //网卡
    WINTUN_SESSION_HANDLE Session;  //会话
    HANDLE QuitEvent;               //退出事件
    int HaveQuit;
    uv_async_t async;               //同步对象
    QUEUE wq;                       //队列
    int write;                      //锁
    int read;
    uint8_t ipv4[4];                        //ipv4地址
    uint8_t ipv6[16];                       //ipv6地址
    opc_vpc* vpc;
}win_tun;

static inline void rwlock_rlock(win_tun* lock) {
    for (;;) {
        while (lock->write) {
            _mm_mfence();
        }
        InterlockedExchangeAdd(&lock->read, 1);
        if (lock->write) {
            InterlockedExchangeAdd(&lock->read, -1);
        }
        else {
            break;
        }
    }
}
static inline void rwlock_wlock(win_tun* lock) {
    while (InterlockedExchange(&lock->write, 1)) {}
    while (lock->read) {
        _mm_mfence();
    }
}
static inline void rwlock_wunlock(win_tun* lock) {
    InterlockedExchange(&lock->write, 0);
}
static inline void rwlock_runlock(win_tun* lock) {
    InterlockedExchangeAdd(&lock->read, -1);
}

#define QUEUE_NEXT(q)       (*(QUEUE **) &((*(q))[0]))
#define QUEUE_PREV(q)       (*(QUEUE **) &((*(q))[1]))
#define QUEUE_PREV_NEXT(q)  (QUEUE_NEXT(QUEUE_PREV(q)))
#define QUEUE_NEXT_PREV(q)  (QUEUE_PREV(QUEUE_NEXT(q)))

#define QUEUE_INSERT_TAIL(h, q)                                               \
  do {                                                                        \
    QUEUE_NEXT(q) = (h);                                                      \
    QUEUE_PREV(q) = QUEUE_PREV(h);                                            \
    QUEUE_PREV_NEXT(q) = (q);                                                 \
    QUEUE_PREV(h) = (q);                                                      \
  }                                                                           \
  while (0)
#define QUEUE_EMPTY(q)                                                        \
  ((const QUEUE *) (q) == (const QUEUE *) QUEUE_NEXT(q))
#define QUEUE_HEAD(q)                                                         \
  (QUEUE_NEXT(q))
#define QUEUE_REMOVE(q)                                                       \
  do {                                                                        \
    QUEUE_PREV_NEXT(q) = QUEUE_NEXT(q);                                       \
    QUEUE_NEXT_PREV(q) = QUEUE_PREV(q);                                       \
  }                                                                           \
  while (0)
#define QUEUE_DATA(ptr, type, field)                                          \
  ((type *) ((char *) (ptr) - offsetof(type, field)))
#define QUEUE_INIT(q)                                                         \
  do {                                                                        \
    QUEUE_NEXT(q) = (q);                                                      \
    QUEUE_PREV(q) = (q);                                                      \
  }                                                                           \
  while (0)
//接口数据
static DWORD WINAPI ReceivePackets(_Inout_ DWORD_PTR Ptr) {
    win_tun* tun = (win_tun*)Ptr;
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(tun->Session), tun->QuitEvent };
    while (!tun->HaveQuit) {
        DWORD PacketSize;
        BYTE* Packet = WintunReceivePacket(tun->Session, &PacketSize);
        if (Packet) {
            //过滤
            uint8_t ip_version = Packet[0] >> 4;
            if (PacketSize < 20) {
                goto end;
            }
            if (ip_version == 4) {
                //目标为非自身网段和自身IP和广播IP不转发
                if ((Packet[16] != tun->ipv4[0] || Packet[17] != tun->ipv4[1]) || (*(uint32_t*)(&tun->ipv4) == *(uint32_t*)(&Packet[16])) || Packet[19] == 0xff) {
                    goto end;
                }
            }
            else if (ip_version == 6 && PacketSize >= 40) {

            }
            else {
                goto end;
            }
            //发给自己的

            //写入
            win_tun_packet* packet = malloc(sizeof(win_tun_packet) + PacketSize);
            if (packet) {
                memset(packet, 0, sizeof(*packet));
                packet->size = PacketSize;
                memcpy(&packet->data, Packet, PacketSize);
                rwlock_wlock(tun);
                QUEUE_INSERT_TAIL(&tun->wq, &packet->wq);
                rwlock_wunlock(tun);
                uv_async_send(&tun->async);
            }
        end:
            WintunReleaseReceivePacket(tun->Session, Packet);
        }
        else {
            DWORD LastError = GetLastError();
            switch (LastError)
            {
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                return ERROR_SUCCESS;
            default:
                return LastError;
            }
        }
    }
    return ERROR_SUCCESS;
}

static void win_tun_async_cb(uv_async_t* handle) {
    win_tun* tun = (win_tun*)handle->data;
    while (1) {
        rwlock_rlock(tun);
        if (QUEUE_EMPTY(&tun->wq)) {
            rwlock_runlock(tun);
            break;
        }
        QUEUE* wq = QUEUE_HEAD(&tun->wq);
        QUEUE_REMOVE(wq);
        rwlock_runlock(tun);
        win_tun_packet* packet = QUEUE_DATA(wq, win_tun_packet, wq);
        vpc_on_packet(tun->vpc, packet->data, packet->size);
        free(packet);
    }
}
//创建
static win_tun* new_tun(opc_vpc* vpc) {
    win_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    tun->vpc = vpc;
    //加载模块
    tun->mod = InitializeWintun();
    if (!tun->mod) {
        free(tun);
        return NULL;
    }
    //创建网卡
    GUID Guid = { vpc->id, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    wchar_t name[256] = { 0 };
    _snwprintf(name, sizeof(name), L"opc %d", vpc->id);
    tun->Adapter = WintunCreateAdapter(name, L"opc", &Guid);
    if (!tun->Adapter) {
        FreeLibrary(tun->mod);
        free(tun);
        return NULL;
    }
    //设置IPv4
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    memcpy(&AddressRow.Address.Ipv4.sin_addr.S_un.S_addr, &vpc->ipv4, sizeof(AddressRow.Address.Ipv4.sin_addr.S_un.S_addr));
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
    AddressRow.DadState = IpDadStatePreferred;
    int LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        FreeLibrary(tun->mod);
        free(tun);
        return NULL;
    }
    memcpy(tun->ipv4, vpc->ipv4, sizeof(tun->ipv4));
    //设置IPv6
    memset(&AddressRow, 0, sizeof(AddressRow));
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv6.sin6_family = AF_INET6;
    memcpy(&AddressRow.Address.Ipv6.sin6_addr.u.Byte, &vpc->ipv6, sizeof(AddressRow.Address.Ipv6.sin6_addr.u.Byte));
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        FreeLibrary(tun->mod);
        free(tun);
        return NULL;
    }
    memcpy(tun->ipv6, vpc->ipv6, sizeof(tun->ipv6));
    //创建同步对象
    tun->async.data = tun;
    uv_async_init(loop, &tun->async, win_tun_async_cb);
    QUEUE_INIT(&tun->wq);
    //启动会话
    tun->Session = WintunStartSession(tun->Adapter, 0x400000);
    tun->QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    //创建接收线程
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)tun, 0, NULL);
    return tun;
}
//往接口发送数据
static void send_tun(opc_vpc* vpc, const char* data, int size) {
    win_tun* tun = vpc->data;
    BYTE* Packet = WintunAllocateSendPacket(tun->Session, size);
    if (Packet) {
        memcpy(Packet, data, size);
        WintunSendPacket(tun->Session, Packet);
    }
}
#else

#include <linux/if_tun.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>


typedef struct _linux_tun {
    int fd;
    uint8_t ipv4[4];                        //ipv4地址
    uint8_t ipv6[16];                       //ipv6地址
    opc_vpc* vpc;
}linux_tun;

//创建
static linux_tun* new_tun(opc_vpc* vpc) {
    linux_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    tun->vpc = vpc;

    if ((tun->fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        return  NULL;
    }


    char dev[256]={0};
    snprintf(dev, sizeof(dev), "opc%d", tun->vpc->id);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
   
    // 获得网络接口的flag
    ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;
 
    // 设置网络结构的参数
    //  此时还没有设置IP地址
    ioctl(tun->fd, TUNSETIFF, (void *)&ifr);

    

}

//往接口发送数据
static void send_tun(opc_vpc* vpc, const char* data, int size) {

}

#endif

static uint16_t ip_checksum(uint8_t* buf, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2, buf += 2)
        sum += *(uint16_t*)buf;
    if (len)
        sum += *buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

//收到接口数据包
static vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size) {
    //发送数据
    bridge_send(vpc->bridge, ops_packet_vpc_data, vpc->vid, vpc->id, packet, size);
}
static void vpc(opc_bridge* bridge, ops_packet* packet) {
    int count = ntohl(*(uint32_t*)&packet->data[0]);
    char* pos = &packet->data[4];
    for (size_t i = 0; i < count; i++) {
        ops_member mem;
        memcpy(&mem, pos, sizeof(mem));
        pos += sizeof(mem);
        mem.id = ntohl(mem.id);
        mem.vid = ntohs(mem.vid);

        opc_vpc* vpc = (opc_vpc*)malloc(sizeof(*vpc));
        if (!vpc) {
            continue;
        }
        memset(vpc, 0, sizeof(*vpc));
        vpc->bridge = bridge;
        vpc->id = mem.id;
        vpc->vid = mem.vid;
        memcpy(&vpc->ipv4, &mem.ipv4, sizeof(vpc->ipv4));
        memcpy(&vpc->ipv6, &mem.ipv6, sizeof(vpc->ipv6));
        //创建接口
        vpc->data = new_tun(vpc);
        //记录
        RB_INSERT(_opc_vpc_tree, &bridge->vpc, vpc);
    }

}
static void vpc_data(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_vpc the = {
        .id = packet->stream_id
    };
    opc_vpc* vpc = RB_FIND(_opc_vpc_tree, &bridge->vpc, &the);
    if (!vpc) {
        return;
    }
    //处理icmp,ping命令
    uint8_t* data = packet->data;
    uint8_t ip_version = data[0] >> 4, proto;
    if (ip_version == 4 && data[9] == 1 && data[20] == 8) {
        //修改目标地址
        uint8_t tmp[4];
        memcpy(tmp, &data[12], 4);
        memcpy(&data[12], &data[16], 4);
        memcpy(&data[16], tmp, 4);
        *(uint16_t*)&data[10] = 0;//清零
        *(uint16_t*)&data[10] = ip_checksum(data, 20);
        data[20] = 0;//ping 应答
        *(uint16_t*)&data[22] = 0;//清零
        *(uint16_t*)&data[22] = ip_checksum(&data[20], size - 20);
        bridge_send(vpc->bridge, ops_packet_vpc_data, vpc->vid, vpc->id, data, size);
        return;
    }
    else if (ip_version == 6 && data[6] == 1 && data[40] == 8) {
        //修改目标地址
        uint8_t tmp[16];
        memcpy(tmp, &data[8], 16);
        memcpy(&data[8], &data[24], 16);
        memcpy(&data[24], tmp, 16);
        data[40] = 0;//ping 应答
        *(uint16_t*)&data[42] = 0;//清零
        *(uint16_t*)&data[42] = ip_checksum(&data[40], size - 40);
        bridge_send(vpc->bridge, ops_packet_vpc_data, vpc->vid, vpc->id, data, size);
        return;
    }
    send_tun(vpc, packet->data, size);
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
static void bridge_keep_timer_cb(uv_timer_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    //检查是否超时


    uint8_t buf[12];
    *(uint64_t *)&buf[0] = uv_hrtime();
    *(uint32_t*)&buf[8] = htonl(bridge->keep_ttl);
    bridge_send(bridge, ops_packet_ping, 0, 0, buf, sizeof(buf));
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
            //启动定时器
            uv_timer_start(&bridge->keep_timer, bridge_keep_timer_cb, 1000 * 10, 1000 * 10);
        }
        else {
            printf("Auth Err!\r\n");
        }
        break;
    }
    case ops_packet_ping: {
        uint64_t t = *(uint64_t*)&packet->data[0];
        bridge->keep_last = uv_hrtime();
        bridge->keep_ping = bridge->keep_last - t;
        break;
    }
    case ops_packet_forward: {//下发转发服务
        forward(bridge, packet);
        break;
    }
    case ops_packet_forward_ctl: {//转发控制指令
        forward_ctl(bridge, packet);
        break;
    }
    case ops_packet_forward_data_local: {//本地来的转发数据
        forward_data_local(bridge, packet, size);
        break;
    }
    case ops_packet_forward_data_remote: {//远程来的转发数据
        forward_data_remote(bridge, packet, size);
        break;
    }
    case ops_packet_host: {
        host(bridge, packet);
        break;
    }
    case ops_packet_host_ctl: {//域名控制服务
        host_ctl(bridge, packet);
        break;
    }
    case ops_packet_host_data: {
        host_data(bridge, packet, size);
        break;
    }
    case ops_packet_vpc: {
        vpc(bridge, packet);
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
//重连回调
static int start_connect(opc_global* global);
void bridge_re_timer_cb(uv_timer_t* handle) {
    start_connect((opc_global*)handle->data);
}
//关闭
static void bridge_close_cb(uv_handle_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    bridge->global->bridge = NULL;
    //定时重连
    uv_timer_start(&bridge->global->re_timer, bridge_re_timer_cb, 1000 * 5, 0);
    //回收资源
    databuffer_clear(&bridge->m_buffer, &bridge->global->m_mp);
    //
    opc_forward_tunnel_src* sc = NULL;
    opc_forward_tunnel_src* scc = NULL;
    RB_FOREACH_SAFE(sc, _opc_forward_tunnel_src_tree, &bridge->tunnel_src, scc) {
        RB_REMOVE(_opc_forward_tunnel_src_tree, &bridge->tunnel_src, sc);
        free(sc);
        sc = NULL;
    }
    opc_forward_tunnel_dst* dc = NULL;
    opc_forward_tunnel_dst* dcc = NULL;
    RB_FOREACH_SAFE(dc, _opc_forward_tunnel_dst_tree, &bridge->tunnel_dst, dcc) {
        RB_REMOVE(_opc_forward_tunnel_dst_tree, &bridge->tunnel_dst, dc);
        free(dc);
        dc = NULL;
    }

    free(bridge);
}
static void bridge_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    uv_close(&bridge->tcp, bridge_close_cb);
    free(req);
}
//数据到达
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_bridge* bridge = (opc_bridge*)tcp->data;
    opc_global* global = bridge->global;
    if (nread <= 0) {
        printf("Server Disconnected\r\n");
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
//连接返回
static void bridge_connect_cb(uv_connect_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    free(req);
    if (status < 0) {
        printf("Connect Error %s\r\n", uv_strerror(status));
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
    uv_timer_init(loop, &bridge->keep_timer);
    bridge->keep_timer.data = bridge;
    uv_tcp_init(loop, &bridge->tcp);
    bridge->tcp.data = bridge;
    req->data = bridge;
    struct sockaddr_in _addr;
    uv_ip4_addr(global->config.server_ip, global->config.server_port, &_addr);
    uv_tcp_connect(req, &bridge->tcp, &_addr, bridge_connect_cb);
    printf("Start Connect\r\n");
    return 0;
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
