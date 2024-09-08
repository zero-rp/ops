#include <uv.h>
#include <cJSON.h>
#include <uv/tree.h>
#include <openssl/ssl.h>
#include "databuffer.h"
#include "common.h"
#include "obj.h"

#if HAVE_QUIC
#include <lsquic.h>
#endif

#define DEFAULT_BACKLOG 128

//目标隧道
typedef struct _opc_dst_tunnel {
    RB_ENTRY(_opc_dst_tunnel) entry;        //
    obj_field ref;                                        //计数
    uint32_t stream_id;                             //流ID
    uint32_t pree_id;                               //对端流ID
    uv_tcp_t tcp;                                   //
    uv_connect_t req;
    uv_getaddrinfo_t req_info;
    struct _opc_dst* dst;
    struct _opc_bridge* bridge;
}opc_dst_tunnel;
RB_HEAD(_opc_dst_tunnel_tree, _opc_dst_tunnel);
//目标
typedef struct _opc_dst {
    RB_ENTRY(_opc_dst) entry;                       //
    obj_field ref;                                  //计数
    uint32_t id;                                    //转发服务ID
    char bind[256];                                 //绑定本地地址
    char dst[256];                                  //目标
    uint16_t port;                                  //目标端口
}opc_dst;
RB_HEAD(_opc_dst_tree, _opc_dst);
//转发隧道
typedef struct _opc_forward_tunnel {
    RB_ENTRY(_opc_forward_tunnel) entry;        //
    obj_field ref;                                        //计数
    uint32_t stream_id;                             //流ID
    uint32_t pree_id;                               //对端流ID
    union {
        uv_tcp_t tcp;                                   //
    };
    uint8_t handshake;                              //握手进度
    struct _opc_forward* src;
    struct _opc_bridge* bridge;
}opc_forward_tunnel;
RB_HEAD(_opc_forward_tunnel_tree, _opc_forward_tunnel);
//转发
typedef struct _opc_forward {
    RB_ENTRY(_opc_forward) entry;               //
    obj_field ref;                                        //计数
    uint32_t id;                                    //转发服务ID
    uint8_t type;                                   //转发类型
    union {
        struct {
            uv_tcp_t tcp;                           //监听
            union {
                struct {
                    char* user;
                    char* pass;
                }socks5;
            };
        }tcp;
        struct {
            uv_udp_t udp;                           //监听
        }udp;
    };
    struct _opc_bridge* bridge;
}opc_forward;
RB_HEAD(_opc_forward_tree, _opc_forward);
//VPC
typedef struct _opc_vpc {
    RB_ENTRY(_opc_vpc) entry;                       //
    obj_field ref;                                        //计数
    uint32_t id;                                    //成员id
    uint16_t vid;                                   //
    struct in_addr ipv4;                            //ipv4地址
    struct in_addr ipv4_mask;                       //ipv4掩码
    uint8_t prefix_v4;                              //ipv4前缀
    struct in6_addr ipv6;                           //ipv6地址
    struct in6_addr ipv6_mask;                      //ipv6掩码
    uint8_t prefix_v6;                              //ipv6前缀
    void* data;                                     //接口数据
    struct _opc_bridge* bridge;
}opc_vpc;
RB_HEAD(_opc_vpc_tree, _opc_vpc);
typedef struct _send_buffer {
    uint8_t* data;
    uint32_t size;
    uint32_t pos;
    struct _send_buffer* next;
}send_buffer;
//网桥
typedef struct _opc_bridge {
    obj_field ref;                                      //计数
    uv_tcp_t tcp;                                       //服务器通讯句柄
    lsquic_conn_t* conn;
    lsquic_stream_t* stream;                            //quic
    send_buffer* send;                                  //发送缓冲
    send_buffer* tail;                                  //发送缓冲尾
    struct _opc_global* global;
    struct databuffer m_buffer;                         //接收缓冲
    uv_timer_t keep_timer;                              //心跳,重鉴权定时器
    uint64_t keep_last;                                 //上次心跳
    uint32_t keep_ping;                                 //延迟
    struct {
        uint8_t quit : 1;                               //当前连接已退出
    } b;
    //----------------------------
    struct _opc_dst_tunnel_tree dst_tunnel;     //
    struct _opc_dst_tree dst;
    //----------------------------
    uint32_t forward_tunnel_id;                         //转发流ID分配
    struct _opc_forward_tunnel_tree forward_tunnel;     //
    struct _opc_forward_tree forward;
    //----------------------------
    struct _opc_vpc_tree vpc;
}opc_bridge;
//配置
typedef struct _opc_config {
    const char* auth_key;       //web api密钥
    const char* server_ip;      //服务器IP
    const char* bind_ip;        //连接服务器使用的本地ip
    uint16_t server_port;       //服务器端口
    uint16_t use_quic;          //是否使用quic
}opc_config;
//
typedef struct _opc_global {
    uv_tcp_t tcp;                       //连接
    struct messagepool m_mp;            //接收缓冲
#if HAVE_QUIC
    struct {
        uv_udp_t udp;
        uv_timer_t event;
        struct lsquic_stream_if stream_if;
        struct lsquic_engine_api engine_api;
        struct lsquic_engine_settings engine_settings;
        lsquic_engine_t* engine;
        SSL_CTX* ssl_ctx;
        char* token;
        int token_len;
    }quic;
#endif
    uv_timer_t re_timer;                //重连定时器
    struct _opc_bridge* bridge;
    opc_config config;                  //
}opc_global;

static uv_loop_t* loop = NULL;

static int _opc_dst_compare(opc_dst* w1, opc_dst* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_dst_tree, _opc_dst, entry, _opc_dst_compare)
static int _opc_dst_tunnel_compare(opc_dst_tunnel* w1, opc_dst_tunnel* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_dst_tunnel_tree, _opc_dst_tunnel, entry, _opc_dst_tunnel_compare)
static int _opc_forward_compare(opc_forward* w1, opc_forward* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tree, _opc_forward, entry, _opc_forward_compare)
static int _opc_forward_tunnel_compare(opc_forward_tunnel* w1, opc_forward_tunnel* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_tree, _opc_forward_tunnel, entry, _opc_forward_tunnel_compare)
static int _opc_vpc_compare(opc_vpc* w1, opc_vpc* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_vpc_tree, _opc_vpc, entry, _opc_vpc_compare)

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
//
static void bridge_send(opc_bridge* bridge, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
//--------------------------------------------------------------------------------------------------------dst
#if 1
//--------------------------隧道
static void dst_tunnel_free(opc_dst_tunnel* p) {
    RB_REMOVE(_opc_dst_tunnel_tree, &p->bridge->dst_tunnel, p);
    obj_unref(p->dst);//ref_16
    obj_unref(p->bridge);//ref_17
}
//失败关闭对端隧道
static void dst_tunnel_err(opc_bridge* bridge, uint32_t service_id, uint32_t stream_id) {
    uint8_t buf[1];
    buf[0] = CTL_DST_CTL_ERR;//连接失败
    bridge_send(bridge, ops_packet_dst_ctl, service_id, stream_id, buf, sizeof(buf));
}
//目标连接关闭
static void dst_tunnel_close_cb(uv_handle_t* handle) {
    opc_dst_tunnel* tunnel = (opc_dst_tunnel*)handle->data;
    dst_tunnel_err(tunnel->bridge, tunnel->dst->id, tunnel->pree_id);
    obj_unref(tunnel);//ref_18
    obj_unref(tunnel);//ref_14
}
static void dst_tunnel_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_dst_tunnel* tunnel = (opc_dst_tunnel*)req->data;
    uv_close((uv_handle_t*)&tunnel->tcp, dst_tunnel_close_cb);
    obj_unref(tunnel);//ref_20
    free(req);
}
static void dst_tunnel_shutdown(opc_dst_tunnel* tunnel) {
    uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
    if (req != NULL) {
        memset(req, 0, sizeof(*req));
        req->data = obj_ref(tunnel);//ref_20
        uv_shutdown(req, (uv_stream_t*)&tunnel->tcp, dst_tunnel_shutdown_cb);
    }
    else {
        //分配内存失败,直接强制关闭
        uv_close((uv_handle_t*)&tunnel->tcp, dst_tunnel_close_cb);
    }
}
//目标数据到达
static void dst_tunnel_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_dst_tunnel* tunnel = (opc_dst_tunnel*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close((uv_handle_t*)tcp, dst_tunnel_close_cb);
        }
        else {
            //shutdown
            dst_tunnel_shutdown(tunnel);
        }
        return;
    }
    //转发
    bridge_send(tunnel->bridge, ops_packet_dst_data, tunnel->dst->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//连接返回
static void dst_tunnel_connect_cb(uv_connect_t* req, int status) {
    opc_dst_tunnel* tunnel = req->data;
    obj_unref(tunnel);//ref_19
    if (status < 0) {
        //连接失败
        dst_tunnel_err(tunnel->bridge, tunnel->dst->id, tunnel->pree_id);
        //关闭连接
        uv_close((uv_handle_t*)&tunnel->tcp, dst_tunnel_close_cb);
        return;
    }
    //通知成功
    uint8_t buf[5];
    buf[0] = CTL_DST_CTL_SUC;//连接成功
    *(uint32_t*)(&buf[1]) = htonl(tunnel->stream_id);
    bridge_send(tunnel->bridge, ops_packet_dst_ctl, tunnel->dst->id, tunnel->pree_id, buf, sizeof(buf));
    //连接远端成功
    uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, dst_tunnel_read_cb);
}
//转发隧道解析目标主机
static void dst_tunnel_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_dst_tunnel* tunnel = req->data;
    obj_unref(tunnel);//ref_15
    if (status != 0) {
        //通知失败
        dst_tunnel_err(tunnel->bridge, tunnel->dst->id, tunnel->pree_id);
        printf("No DNS Forward Id %d\r\n", tunnel->dst->id);
        return;
    }
    uv_tcp_init(loop, &tunnel->tcp);
    tunnel->tcp.data = obj_ref(tunnel);//ref_18
    //绑定本地地址
    int bind_family = 0;
    if (strlen(tunnel->dst->bind) > 0) {
        struct sockaddr_in6 addr;
        if (uv_ip6_addr(tunnel->dst->bind, 0, &addr) == 0) {
            bind_family = addr.sin6_family;
            uv_tcp_bind(&tunnel->req, &addr, 0);
        }
        else if (uv_ip4_addr(tunnel->dst->bind, 0, &addr) == 0) {
            bind_family = addr.sin6_family;
            uv_tcp_bind(&tunnel->req, &addr, 0);
        }
    }
    struct addrinfo* addr = res;
    //选择协议栈
    if (bind_family && addr) {
        do {
            if (addr->ai_family == bind_family) {
                break;
            }
            addr = addr->ai_next;
        } while (addr);
    }
    tunnel->req.data = obj_ref(tunnel);//ref_19
    if (addr) {
        uv_tcp_connect(&tunnel->req, &tunnel->tcp, addr->ai_addr, dst_tunnel_connect_cb);
    }
    else {
        //通知失败
        dst_tunnel_err(tunnel->bridge, tunnel->dst->id, tunnel->pree_id);
    }
    //释放结果
    uv_freeaddrinfo(res);
}
//新目标隧道
static opc_dst_tunnel* dst_tunnel_new(opc_bridge* bridge, opc_dst* dst, uint32_t pree_id, uint8_t* data, int size) {
    obj_new(tunnel, opc_dst_tunnel);//ref_14
    if (!tunnel)
        return NULL;
    tunnel->ref.del = dst_tunnel_free;

    tunnel->dst = obj_ref(dst);//ref_16
    tunnel->bridge = obj_ref(bridge);//ref_17

    tunnel->stream_id = bridge->forward_tunnel_id++;
    tunnel->pree_id = pree_id;
    RB_INSERT(_opc_dst_tunnel_tree, &bridge->dst_tunnel, tunnel);
    //开始连接,解析主机
    tunnel->req_info.data = obj_ref(tunnel);//ref_15
    //动态目标处理
    if (data && size) {
        uint16_t port = ntohs(*(uint16_t*)(&data[1]));
        char buf[10] = { 0 };
        snprintf(buf, sizeof(buf), "%d", port);
        char addr[256] = { 0 };
        memcpy(addr, &data[3], data[0]);
        addr[data[0]] = 0;
        uv_getaddrinfo(loop, &tunnel->req_info, dst_tunnel_getaddrinfo_cb, addr, buf, NULL);
    }
    else {
        char buf[10] = { 0 };
        snprintf(buf, sizeof(buf), "%d", dst->port);
        uv_getaddrinfo(loop, &tunnel->req_info, dst_tunnel_getaddrinfo_cb, dst->dst, buf, NULL);
    }
    return tunnel;
}
//--------------------------目标
//新转发目标
static int dst_new(opc_bridge* bridge, ops_dst* dst) {
    obj_new(d, opc_dst);//ref_23
    if (!d) {
        return -1;
    }
    d->ref.del = NULL;
    d->id = dst->sid;
    memcpy(d->dst, dst->dst, sizeof(d->dst));
    d->dst[sizeof(d->dst) - 1] = 0;
    memcpy(d->bind, dst->bind, sizeof(d->bind));
    d->bind[sizeof(d->bind) - 1] = 0;
    d->port = dst->port;

    RB_INSERT(_opc_dst_tree, &bridge->dst, d);
    return 0;
}
//删除转发目标
static void dst_del(opc_bridge* bridge, opc_dst* dst) {
    RB_REMOVE(_opc_dst_tree, &bridge->dst, dst);
    obj_unref(dst);//ref_23
}
//-----------------------------------------------------服务器控制回调
static void dst(opc_bridge* bridge, ops_packet* packet) {
    uint8_t ctl = packet->data[0];
    char* pos = &packet->data[1];
    switch (ctl)
    {
    case CTL_DST_ADD: {
        uint32_t count = ntohl(*(uint32_t*)pos);
        pos += 4;
        for (size_t i = 0; i < count; i++) {
            ops_dst dst;
            memcpy(&dst, pos, sizeof(dst));
            pos += sizeof(dst);
            dst.sid = ntohl(dst.sid);
            dst.port = ntohs(dst.port);
            if (dst_new(bridge, &dst) == 0) {
                printf("Load Dst id:[%d],dst:[%s],dst_port:[%d]\r\n", dst.sid, dst.dst, dst.port);
            }
        }
        break;
    }
    case CTL_DST_DEL: {
        uint32_t sid = ntohl(*(uint32_t*)pos);


        break;
    }
    default:
        break;
    }
}
static void dst_ctl(opc_bridge* bridge, ops_packet* packet, int size) {
    uint8_t type = packet->data[0];
    switch (type)
    {
    case CTL_DST_CTL_OPEN: {//发起请求
        //查找目标服务
        printf("New DST Request For Id %d\r\n", packet->service_id);
        opc_dst ths = {
            .id = packet->service_id
        };
        opc_dst* dst = RB_FIND(_opc_dst_tree, &bridge->dst, &ths);
        if (dst == NULL) {
            printf("No Find Forward Id %d\r\n", packet->service_id);
            dst_tunnel_err(bridge, packet->service_id, packet->stream_id);
            break;
        }
        //请求连接远端
        opc_dst_tunnel* tunnel = dst_tunnel_new(bridge, dst, packet->stream_id, size > 1 ? &packet->data[1] : NULL, size - 1);
        if (!tunnel) {
            dst_tunnel_err(bridge, packet->service_id, packet->stream_id);
            break;
        }
        break;
    }
    case CTL_DST_CTL_ERR: { //异常
        opc_dst_tunnel the = {
            .stream_id = packet->stream_id
        };
        opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &bridge->dst_tunnel, &the);
        if (!tunnel) {
            //连接已经不存在了,丢弃
            break;
        }
        //失败或异常,将本地连接关闭
        dst_tunnel_shutdown(tunnel);
        /*
         if (packet->data[1] == 0x02) {
            //成功
            //读取对端流ID
            tunnel->pree_id = ntohl(*(uint32_t*)(&packet->data[2]));
            //开始接收本地数据
            uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_read_cb);
        }*/
        break;
    }

    case 0x05: {//来自来源的应答
        opc_dst_tunnel the = {
            .stream_id = packet->stream_id
        };
        opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &bridge->dst_tunnel, &the);
        if (!tunnel) {
            //连接已经不存在了,丢弃
            break;
        }
        if (packet->data[1] == 0x01) {
            //来源方向异常
            dst_tunnel_shutdown(tunnel);
        }
        break;
    }
    default:
        break;
    }
}
static void dst_data(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_dst_tunnel  the = {
        .stream_id = packet->stream_id
    };
    opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &bridge->dst_tunnel, &the);
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
    uv_write(req, (uv_stream_t*)&tunnel->tcp, &buf, 1, write_cb);
}
//回收资源
static void dst_free(opc_bridge* bridge) {
    //关闭目标隧道
    opc_dst_tunnel* dc = NULL;
    opc_dst_tunnel* dcc = NULL;
    RB_FOREACH_SAFE(dc, _opc_dst_tunnel_tree, &bridge->dst_tunnel, dcc) {
        dst_tunnel_shutdown(dc);
        dc = NULL;
    }
    //关闭目标
    opc_dst* fdc = NULL;
    opc_dst* fdcc = NULL;
    RB_FOREACH_SAFE(fdc, _opc_dst_tree, &bridge->dst, fdcc) {
        dst_del(bridge, fdc);
        fdc = NULL;
    }

}
#endif
//--------------------------------------------------------------------------------------------------------forward
#if 1
//--------------------------隧道
static void forward_tunnel_free(opc_forward_tunnel* p) {
    RB_REMOVE(_opc_forward_tunnel_tree, &p->bridge->forward_tunnel, p);
    obj_unref(p->bridge);//ref_12
    obj_unref(p->src);//ref_11
}
//失败关闭对端隧道
static void forward_tunnel_err(opc_bridge* bridge, uint32_t service_id, uint32_t stream_id) {
    uint8_t buf[1];
    buf[0] = CTL_FORWARD_CTL_ERR;//连接失败
    bridge_send(bridge, ops_packet_forward_ctl, service_id, stream_id, buf, sizeof(buf));
}
//来源连接关闭
static void forward_tunnel_close_cb(uv_handle_t* handle) {
    opc_forward_tunnel* tunnel = (opc_forward_tunnel*)handle->data;
    forward_tunnel_err(tunnel->bridge, tunnel->src->id, tunnel->pree_id);
    obj_unref(tunnel);//ref_8
    obj_unref(tunnel);//ref_7
}
static void forward_tunnel_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_forward_tunnel* tunnel = (opc_forward_tunnel*)req->data;
    uv_close((uv_handle_t*)&tunnel->tcp, forward_tunnel_close_cb);
    obj_unref(tunnel);//ref_13
    free(req);
}
static void forward_tunnel_shutdown(opc_forward_tunnel* tunnel) {
    uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
    if (req != NULL) {
        memset(req, 0, sizeof(*req));
        req->data = obj_ref(tunnel);//ref_13
        uv_shutdown(req, (uv_stream_t*)&tunnel->tcp, forward_tunnel_shutdown_cb);
    }
    else {
        //分配内存失败,直接强制关闭
        uv_close((uv_handle_t*)&tunnel->tcp, forward_tunnel_close_cb);
    }
}
//发送数据给来源
static void forward_tunnel_send(opc_forward_tunnel* tunnel, uint8_t* data, int size) {
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(size);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tunnel->tcp, &buf, 1, write_cb);
}
//握手
static void forward_tunnel_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf);
static void forward_tunnel_handshake(opc_forward_tunnel* tunnel, uint8_t* data, int size) {
    switch (tunnel->src->type)
    {
    case FORWARD_TYPE_SOCKS5: {
        switch (tunnel->handshake)
        {
        case 0: {
            int auth = (tunnel->src->tcp.socks5.user && tunnel->src->tcp.socks5.pass);
            if (data[0] == 0x05 && (data[1] + 2 == size)) {
                uint8_t tmp[2];
                tmp[0] = 0x05;
                if (data[2] == 0) {
                    //无需认证
                    tmp[1] = 0;
                    //跳到认证完毕
                    tunnel->handshake += 2;
                }
                else if (data[2] == 0x02) {
                    //需要认证,账号密码
                    if (tunnel->src->tcp.socks5.pass && tunnel->src->tcp.socks5.user) {
                        tmp[1] = 0x02;
                        tunnel->handshake++;
                    }
                    else {
                        //没有配置账号密码,

                    }
                }
                //发送第一个握手包
                forward_tunnel_send(tunnel, tmp, 2);
            }
            else {

            }
            break;
        }
        case 1: {
            //认证
            if (data[0] == 0x01 && size > 3) {
                uint8_t u_l, p_l;
                char tmp[2];
                tmp[0] = 0x01;
                u_l = data[1];
                if (size < u_l + 4) {
                    //异常数据
                }
                p_l = data[2 + u_l];
                if (size != u_l + p_l + 3) {
                    //异常数据
                }
                if (memcmp(tunnel->src->tcp.socks5.user, &data[2], u_l) == 0 && memcmp(tunnel->src->tcp.socks5.pass, &data[3 + u_l], p_l) == 0) {
                    tmp[1] = 0x00;
                }
                else {
                    tmp[1] = 0x01;
                }
                forward_tunnel_send(tunnel, tmp, 2);
            }
            else {

            }
            tunnel->handshake++;
            break;
        }
        case 2: {
            //远程请求
            if (data[0] == 0x05 && data[2] == 0x00 && size > 6) {
                //CONNECT
                if (data[1] == 0x01) {
                    char dst[256] = { 0x0 };
                    uint16_t port = 0;
                    if (data[3] == 0x01 && size == 10) {
                        //IPV4
                        struct sockaddr_in in;
                        in.sin_family = AF_INET;
                        memcpy(&in.sin_addr, &data[4], 4);
                        memcpy(&in.sin_port, &data[8], 2);
                        uv_ip4_name(&in, dst, sizeof(dst));
                    }
                    if (data[3] == 0x04 && size == 22) {
                        //IPV6
                        struct sockaddr_in6 in;
                        in.sin6_family = AF_INET6;
                        memcpy(&in.sin6_addr, &data[4], 16);
                        memcpy(&in.sin6_port, &data[20], 2);
                        uv_ip6_name(&in, dst, sizeof(dst));
                    }
                    else if (data[3] == 0x03) {
                        //域名
                        memcpy(dst, &data[5], data[4]);
                        dst[data[4]] = 0;
                        memcpy(&port, &data[data[4] + 4 + 1], 2);
                    }
                    else {
                        //未知的地址类型

                    }
                    printf("Open socks5 %s:%d\r\n", dst, ntohs(port));
                    //发起远程请求
                    uint8_t buf[1 + 1 + 2 + 256];
                    buf[0] = CTL_FORWARD_CTL_OPEN;
                    buf[1] = strlen(dst);//地址长度
                    memcpy(&buf[2], &port, 2);
                    memcpy(&buf[4], dst, buf[1]);
                    bridge_send(tunnel->bridge, ops_packet_forward_ctl, tunnel->src->id, tunnel->stream_id, buf, sizeof(buf));
                }
                tunnel->handshake++;
            }
            else {
                //异常数据

            }
            break;
        }
        case 3: {
            tunnel->handshake = 0xFF;
            //发送应答成功
            uint8_t resp[254 + 6];
            int resp_len = 0;
            resp[0] = 0x05;
            resp[1] = 0x00;//SUC
            resp[2] = 0x00;
            //地址
            resp[3] = 0x01;
            resp_len = 10;
            //发送应答
            forward_tunnel_send(tunnel, resp, resp_len);
            break;
        }
        default:
            break;
        }
        break;
    }
    case FORWARD_TYPE_TCP: {
        tunnel->handshake = 0xFF;
        //开始接收本地数据
        uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_read_cb);
        break;
    }
    default:
        break;
    }
}
//转发隧道来源数据到达
static void forward_tunnel_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_forward_tunnel* tunnel = (opc_forward_tunnel*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close((uv_handle_t*)tcp, forward_tunnel_close_cb);
        }
        else {
            //shutdown
            forward_tunnel_shutdown(tunnel);
        }
        return;
    }
    //转发
    if (tunnel->handshake == 0xFF) {
        bridge_send(tunnel->bridge, ops_packet_forward_data, tunnel->src->id, tunnel->pree_id, buf->base, nread);
    }
    else {
        forward_tunnel_handshake(tunnel, buf->base, nread);
    }
    free(buf->base);
}
//--------------------------源
//转发连接进入
static void forward_connection_cb(uv_stream_t* tcp, int status) {
    opc_forward* src = (opc_forward*)tcp->data;
    obj_new(tunnel, opc_forward_tunnel);//ref_7
    if (!tunnel)
        return;
    tunnel->ref.del = forward_tunnel_free;

    uv_tcp_init(loop, &tunnel->tcp);//初始化tcp bridge句柄
    tunnel->tcp.data = obj_ref(tunnel);//ref_8

    if (uv_accept(tcp, (uv_stream_t*)&tunnel->tcp) == 0) {
        //记录
        tunnel->bridge = obj_ref(src->bridge);//ref_12
        tunnel->src = obj_ref(src);//ref_11
        tunnel->stream_id = tunnel->bridge->forward_tunnel_id++;
        RB_INSERT(_opc_forward_tunnel_tree, &src->bridge->forward_tunnel, tunnel);
        //日志
        printf("New Forward\r\n");
        //需要先握手获取目标信息
        if (src->type == FORWARD_TYPE_SOCKS5 || src->type == FORWARD_TYPE_HTTP) {
            //开始接收本地数据
            uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, forward_tunnel_read_cb);
        }
        else {
            //打开转发隧道
            uint8_t buf[1];
            buf[0] = CTL_FORWARD_CTL_OPEN;
            bridge_send(src->bridge, ops_packet_forward_ctl, src->id, tunnel->stream_id, buf, sizeof(buf));
        }
    }
    else {
        obj_unref(tunnel);//ref_8
        obj_unref(tunnel);//ref_7
    }
}
static void forward_obj_free(opc_forward* p) {
    RB_REMOVE(_opc_forward_tree, &p->bridge->forward, p);
    obj_unref(p->bridge);//ref_6
}
//转发源监听关闭
static void forward_close_cb(uv_handle_t* handle) {
    opc_forward* src = (opc_forward*)handle->data;
    obj_unref(src);//ref_10
    obj_unref(src);//ref_9
}
//新转发源
static int forward_new(opc_bridge* bridge, ops_forward* src) {
    obj_new(s, opc_forward);//ref_9
    if (!s) {
        return -1;
    }
    s->ref.del = forward_obj_free;
    s->id = src->sid;
    s->type = src->type;
    s->bridge = obj_ref(bridge);//ref_6
    switch (s->type)
    {
    case FORWARD_TYPE_TCP:
    case FORWARD_TYPE_SOCKS5:
    case FORWARD_TYPE_HTTP: {
        uv_tcp_init(loop, &s->tcp.tcp);
        s->tcp.tcp.data = obj_ref(s);//ref_10
        //绑定
        struct sockaddr_in6 _addr;
        uv_ip6_addr("::0", src->port, &_addr);
        uv_tcp_bind(&s->tcp.tcp, &_addr, 0);
        //允许复用
        uv_os_fd_t fd;
        if (uv_fileno(&s->tcp.tcp, &fd) == 0) {
            int val = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        }
        //监听端口
        uv_listen((uv_stream_t*)&s->tcp.tcp, DEFAULT_BACKLOG, forward_connection_cb);
    }
    case FORWARD_TYPE_UDP: {


        break;
    }
    default:
        break;
    }
    RB_INSERT(_opc_forward_tree, &bridge->forward, s);
    return 0;
}
//-----------------------------------------------------服务器控制回调
static void forward(opc_bridge* bridge, ops_packet* packet) {
    uint8_t ctl = packet->data[0];
    char* pos = &packet->data[1];
    switch (ctl)
    {
    case CTL_FORWARD_ADD: {
        uint32_t count = ntohl(*(uint32_t*)pos);
        pos += 4;
        for (size_t i = 0; i < count; i++) {
            ops_forward src;
            memcpy(&src, pos, sizeof(src));
            pos += sizeof(src);
            src.sid = ntohl(src.sid);
            src.port = ntohs(src.port);

            if (forward_new(bridge, &src) == 0) {
                printf("Load Forward id:[%d],src_port:[%d]\r\n", src.sid, src.port);
            }
        }
        break;
    }
    case CTL_FORWARD_DEL: {
        uint32_t sid = ntohl(*(uint32_t*)pos);


        break;
    }
    default:
        break;
    }
}
static void forward_ctl(opc_bridge* bridge, ops_packet* packet) {
    opc_forward_tunnel the = {
        .stream_id = packet->stream_id
    };
    opc_forward_tunnel* tunnel = RB_FIND(_opc_forward_tunnel_tree, &bridge->forward_tunnel, &the);
    if (!tunnel) {
        //连接已经不存在了,丢弃
        return;
    }
    switch (packet->data[0])
    {
    case CTL_FORWARD_CTL_SUC: {
        //读取对端流ID
        tunnel->pree_id = ntohl(*(uint32_t*)(&packet->data[1]));
        forward_tunnel_handshake(tunnel, NULL, 0);
        break;
    }
    case CTL_FORWARD_CTL_ERR: {//失败或异常
        //将本地连接关闭
        forward_tunnel_shutdown(tunnel);
        break;
    }
    default:
        break;
    }
}
static void forward_data(opc_bridge* bridge, ops_packet* packet, int size) {
    opc_forward_tunnel  the = {
        .stream_id = packet->stream_id
    };
    opc_forward_tunnel* tunnel = RB_FIND(_opc_forward_tunnel_tree, &bridge->forward_tunnel, &the);
    if (!tunnel)
        return;
    //转发数据到本地
    forward_tunnel_send(tunnel, packet->data, size);
}
//回收资源
static void forward_free(opc_bridge* bridge) {
    //关闭源隧道
    opc_forward_tunnel* sc = NULL;
    opc_forward_tunnel* scc = NULL;
    RB_FOREACH_SAFE(sc, _opc_forward_tunnel_tree, &bridge->forward_tunnel, scc) {
        forward_tunnel_shutdown(sc);
        sc = NULL;
    }
    //关闭源
    opc_forward* fsc = NULL;
    opc_forward* fscc = NULL;
    RB_FOREACH_SAFE(fsc, _opc_forward_tree, &bridge->forward, fscc) {
        uv_close((uv_handle_t*)&fsc->tcp, forward_close_cb);
        fsc = NULL;
    }
}
#endif
//--------------------------------------------------------------------------------------------------------vpc
#if 1
static void vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size);
static void cidr_to_netmask_v4(int prefix, struct in_addr* netmask) {
    netmask->s_addr = htonl(~((1 << (32 - prefix)) - 1));
}
static void cidr_to_netmask_v6(int prefix, struct in6_addr* netmask) {
    for (int i = 0; i < 16; i++) {
        if (prefix > 8) {
            netmask->s6_addr[i] = 0xFF;
            prefix -= 8;
        }
        else {
            netmask->s6_addr[i] = (0xFF << (8 - prefix)) & 0xFF;
            prefix = 0;
        }
    }
}
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

#if defined(_WIN32) || defined(_WIN64)
#include <iphlpapi.h>
#include "wintun.h"

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
        LoadLibraryA("wintun.dll");
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
    WINTUN_ADAPTER_HANDLE Adapter;  //网卡
    WINTUN_SESSION_HANDLE Session;  //会话
    HANDLE Thread;                  //线程
    HANDLE QuitEvent;               //退出事件
    int HaveQuit;
    uv_async_t async;               //同步对象
    QUEUE wq;                       //队列
    int write;                      //锁
    int read;
    struct in_addr ipv4;                        //ipv4地址
    struct in_addr ipv4_mask;                   //ipv4掩码
    struct in_addr6 ipv6;                       //ipv6地址
    struct in_addr6 ipv6_mask;                  //ipv6掩码
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
                //目标为自身IP和广播IP不转发
                if ((*(uint32_t*)(&tun->ipv4) == *(uint32_t*)(&Packet[16])) || Packet[19] == 0xff) {
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
static HMODULE tun_mod;                    //动态库
//创建
static win_tun* new_tun(opc_vpc* vpc) {
    win_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    //加载模块
    if (!tun_mod) {
        tun_mod = InitializeWintun();
        if (!tun_mod) {
            free(tun);
            return NULL;
        }
    }
    //创建网卡
    GUID Guid = { vpc->id, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    wchar_t name[256] = { 0 };
    _snwprintf(name, sizeof(name), L"opc %d", vpc->id);
    tun->Adapter = WintunCreateAdapter(name, L"opc", &Guid);
    if (!tun->Adapter) {
        free(tun);
        return NULL;
    }
    //设置IPv4
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    memcpy(&AddressRow.Address.Ipv4.sin_addr, &vpc->ipv4, sizeof(AddressRow.Address.Ipv4.sin_addr));
    AddressRow.OnLinkPrefixLength = vpc->prefix_v4;
    AddressRow.DadState = IpDadStatePreferred;
    int LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        free(tun);
        return NULL;
    }
    memcpy(&tun->ipv4, &vpc->ipv4, sizeof(tun->ipv4));
    memcpy(&tun->ipv4_mask, &vpc->ipv4_mask, sizeof(tun->ipv4_mask));
    //设置IPv6
    memset(&AddressRow, 0, sizeof(AddressRow));
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv6.sin6_family = AF_INET6;
    memcpy(&AddressRow.Address.Ipv6.sin6_addr, &vpc->ipv6, sizeof(AddressRow.Address.Ipv6.sin6_addr));
    AddressRow.OnLinkPrefixLength = vpc->prefix_v6;
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        free(tun);
        return NULL;
    }
    memcpy(&tun->ipv6, &vpc->ipv6, sizeof(tun->ipv6));
    memcpy(&tun->ipv6_mask, &vpc->ipv6_mask, sizeof(tun->ipv6_mask));
    //
    tun->vpc = obj_ref(vpc); //ref_24
    //创建同步对象
    tun->async.data = tun;
    uv_async_init(loop, &tun->async, win_tun_async_cb);
    QUEUE_INIT(&tun->wq);
    //启动会话
    tun->Session = WintunStartSession(tun->Adapter, 0x400000);
    tun->QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    //创建接收线程
    tun->Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)tun, 0, NULL);
    return tun;
}
//
static void tun_close_cb(uv_handle_t* handle) {
    win_tun* tun = (win_tun*)handle->data;
    //等待线程退出
    if (tun->Thread) {
        WaitForSingleObject(tun->Thread, INFINITE);
        CloseHandle(tun->Thread);
    }
    //回收队列
    while (1) {
        if (QUEUE_EMPTY(&tun->wq)) {
            break;
        }
        QUEUE* wq = QUEUE_HEAD(&tun->wq);
        QUEUE_REMOVE(wq);
        win_tun_packet* packet = QUEUE_DATA(wq, win_tun_packet, wq);
        free(packet);
    }
    if (tun->Session) {
        WintunEndSession(tun->Session);
    }
    if (tun->Adapter) {
        WintunCloseAdapter(tun->Adapter);
    }
    if (tun->QuitEvent) {
        CloseHandle(tun->QuitEvent);
    }
    obj_unref(tun->vpc);//ref_24
    free(tun);
}
//关闭
static void delete_tun(win_tun* tun) {
    //关闭异步对象
    uv_close(&tun->async, tun_close_cb);
    //通知线程退出
    tun->HaveQuit = TRUE;
    SetEvent(tun->QuitEvent);
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
    uv_tcp_t tcp;
    int fd;
    struct in_addr ipv4;                        //ipv4地址
    struct in_addr ipv4_mask;                   //ipv4掩码
    struct in6_addr ipv6;                       //ipv6地址
    struct in6_addr ipv6_mask;                   //ipv4掩码
    opc_vpc* vpc;
}linux_tun;
static void tun_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    linux_tun* tun = (linux_tun*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        return;
    }
    uint8_t* packet = buf->base;

    //过滤
    uint8_t ip_version = packet[0] >> 4;
    if (nread < 20) {
        goto end;
    }
    if (ip_version == 4) {
        //目标为自身IP和广播IP不转发
        if ((*(uint32_t*)(&tun->ipv4) == *(uint32_t*)(&packet[16])) || packet[19] == 0xff) {
            goto end;
        }
    }
    else if (ip_version == 6 && nread >= 40) {

    }
    else {
        goto end;
    }
    vpc_on_packet(tun->vpc, packet, nread);
end:
    free(buf->base);
}
//创建
static linux_tun* new_tun(opc_vpc* vpc) {
    linux_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    tun->vpc = obj_ref(vpc);//ref_25

    if ((tun->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        free(tun);
        return  NULL;
    }

    int flags = fcntl(tun->fd, F_GETFL);
    fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);

    char dev[256] = { 0 };
    snprintf(dev, sizeof(dev), "opc%d", tun->vpc->id);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);

    // 获得网络接口的flag
    ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;

    // 设置网络结构的参数
    ioctl(tun->fd, TUNSETIFF, (void*)&ifr);

    struct sockaddr_in addr;
    int sockfd, err = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &vpc->ipv4, sizeof(addr.sin_addr));

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

    //设定ip地址
    if ((err = ioctl(sockfd, SIOCSIFADDR, (void*)&ifr)) < 0) {
        perror("ioctl SIOSIFADDR");
        goto done;
    }

    /* 获得接口的标志 */
    if ((err = ioctl(sockfd, SIOCGIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        goto done;
    }
    /* 设置接口的标志 */
    ifr.ifr_flags |= IFF_UP;
    // ifup tap0 #启动设备
    if ((err = ioctl(sockfd, SIOCSIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        goto done;
    }
    //设定子网掩码
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &vpc->ipv4_mask, sizeof(addr.sin_addr));
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if ((err = ioctl(sockfd, SIOCSIFNETMASK, (void*)&ifr)) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        goto done;
    }

    memcpy(&tun->ipv4, &vpc->ipv4, sizeof(tun->ipv4));
    memcpy(&tun->ipv4_mask, &vpc->ipv4_mask, sizeof(tun->ipv4_mask));



    memcpy(&tun->ipv6, &vpc->ipv6, sizeof(tun->ipv6));
    memcpy(&tun->ipv6_mask, &vpc->ipv6_mask, sizeof(tun->ipv6_mask));

done:
    close(sockfd);

    uv_tcp_init(loop, &tun->tcp);
    tun->tcp.data = tun;
    uv_tcp_open(&tun->tcp, tun->fd);
    uv_read_start((uv_stream_t*)&tun->tcp, alloc_buffer, tun_read_cb);
    return tun;
}
static void tun_close_cb(uv_handle_t* handle) {
    linux_tun* tun = (linux_tun*)handle->data;
    obj_unref(tun->vpc);//ref_25
    free(tun);
}
//关闭
static void delete_tun(linux_tun* tun) {
    uv_close(&tun->tcp, tun_close_cb);
}
//往接口发送数据
static void send_tun(opc_vpc* vpc, const char* data, int size) {
    linux_tun* tun = (linux_tun*)(vpc->data);
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tun->tcp, &buf, 1, write_cb);
}
#endif

//收到接口数据包
static void vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size) {
    //发送数据
    bridge_send(vpc->bridge, ops_packet_vpc_data, vpc->vid, vpc->id, packet, size);
}
//
static void vpc_obj_free(opc_vpc* p) {
    RB_REMOVE(_opc_vpc_tree, &p->bridge->vpc, p);
    obj_unref(p->bridge);//ref_22
}
//删除vpc
static void vpc_del(opc_vpc* vpc) {
    if (vpc->data) {
        delete_tun(vpc->data);
    }
    obj_unref(vpc);//ref_21
}
static void vpc(opc_bridge* bridge, ops_packet* packet) {
    uint8_t ctl = packet->data[0];
    char* pos = &packet->data[1];
    switch (ctl)
    {
    case CTL_MEMBER_ADD: {
        int count = ntohl(*(uint32_t*)pos);
        pos += 4;
        for (size_t i = 0; i < count; i++) {
            ops_member mem;
            memcpy(&mem, pos, sizeof(mem));
            pos += sizeof(mem);
            mem.id = ntohl(mem.id);
            mem.vid = ntohs(mem.vid);

            obj_new(vpc, opc_vpc);//ref_21
            if (!vpc) {
                continue;
            }
            vpc->ref.del = vpc_obj_free;
            vpc->bridge = obj_ref(bridge);//ref_22
            vpc->id = mem.id;
            vpc->vid = mem.vid;

            memcpy(&vpc->ipv4, &mem.ipv4, sizeof(vpc->ipv4));
            vpc->prefix_v4 = mem.prefix_v4;
            cidr_to_netmask_v4(mem.prefix_v4, &vpc->ipv4_mask);

            memcpy(&vpc->ipv6, &mem.ipv6, sizeof(vpc->ipv6));
            vpc->prefix_v6 = mem.prefix_v6;
            cidr_to_netmask_v6(mem.prefix_v6, &vpc->ipv6_mask);

            //创建接口
            vpc->data = new_tun(vpc);
            //记录
            RB_INSERT(_opc_vpc_tree, &bridge->vpc, vpc);
        }
        break;
    }
    case CTL_MEMBER_DEL: {
        uint32_t id = ntohl(*(uint32_t*)pos);
        opc_vpc the = {
            .id = id
        };
        opc_vpc* vpc = RB_FIND(_opc_vpc_tree, &bridge->vpc, &the);
        if (vpc) {
            vpc_del(vpc);
        }
        break;
    }
    default:
        break;
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
    uint8_t ip_version = data[0] >> 4;
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
//回收资源
static void vpc_free(opc_bridge* bridge) {
    opc_vpc* c = NULL;
    opc_vpc* cc = NULL;
    RB_FOREACH_SAFE(c, _opc_vpc_tree, &bridge->vpc, cc) {
        vpc_del(c);
        cc = NULL;
    }
}
#endif
//--------------------------------------------------------------------------------------------------------bridge
static void bridge_re_timer_cb(uv_timer_t* handle);
static void quic_process_conns(opc_global* global);

//检查是否退出
static void bridge_check() {

}
//鉴权成功
static void bridge_auth_ok(opc_bridge* bridge) {
    //提交设备信息




}
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
//
static void bridge_keep_close_cb(uv_handle_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    obj_unref(bridge);//ref_4
}
//关闭
static void bridge_on_close(opc_bridge* bridge) {
    if (bridge->global->bridge == bridge) {
        bridge->global->bridge = NULL;
        obj_unref(bridge);//ref_3
    }
    bridge->b.quit = 1;
    //回收资源
    databuffer_clear(&bridge->m_buffer, &bridge->global->m_mp);
    //回收目标
    dst_free(bridge);
    //回收转发器
    forward_free(bridge);
    //回收vpc
    vpc_free(bridge);
    //关闭定时器
    if (bridge->keep_timer.data) {
        uv_close(&bridge->keep_timer, bridge_keep_close_cb);
    }
    //
    obj_unref(bridge);//ref_5
    //
    obj_unref(bridge);//ref_1
    //
}
static void bridge_close_cb(uv_handle_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    bridge_on_close(bridge);
}
static void bridge_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    uv_close(&bridge->tcp, bridge_close_cb);
    free(req);
}
//ping检测定时器
static void bridge_keep_timer_cb(uv_timer_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    //检查是否超时
    if (bridge->keep_last < (loop->time - 1000 * 30)) {
        //暂停掉定时器
        uv_timer_stop(handle);
        //超时直接关闭
        if (bridge->global->config.use_quic) {
            if (bridge->conn) {
                lsquic_conn_close(bridge->conn);
            }
        }
        else {
            uv_close(&bridge->tcp, bridge_close_cb);
        }
        return;
    }
    //
    uint8_t buf[12];
    *(uint64_t*)&buf[0] = loop->time;
    *(uint32_t*)&buf[8] = htonl(bridge->keep_ping);
    bridge_send(bridge, ops_packet_ping, 0, 0, buf, sizeof(buf));
}
//重鉴权定时器
static void bridge_auth_timer_cb(uv_timer_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    bridge_connect_end(bridge);
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
        switch (packet->data[0])
        {
        case CTL_AUTH_ERR: {
            printf("Auth Err!\r\n");
            break;
        }
        case CTL_AUTH_OK: {
            printf("Auth Ok!\r\n");
            //启动定时器
            bridge->keep_last = loop->time;
            uv_timer_start(&bridge->keep_timer, bridge_keep_timer_cb, 0, 1000 * 10);
            bridge_auth_ok(bridge);
            break;
        }
        case CTL_AUTH_ONLINE: {
            printf("Wait ReAuth...\r\n");
            //启动定时器
            uv_timer_start(&bridge->keep_timer, bridge_auth_timer_cb, 1000 * 5, 0);
            break;
        }
        default:
            break;
        }
        break;
    }
    case ops_packet_ping: {
        uint64_t t = *(uint64_t*)&packet->data[0];
        bridge->keep_last = loop->time;
        bridge->keep_ping = bridge->keep_last - t;
        break;
    }
    case ops_packet_dst: {//下发目标
        dst(bridge, packet);
        break;
    }
    case ops_packet_dst_ctl: {//目标控制指令
        dst_ctl(bridge, packet, size);
        break;
    }
    case ops_packet_dst_data: {//目标数据
        dst_data(bridge, packet, size);
        break;
    }
    case ops_packet_forward: {//下发转发
        forward(bridge, packet);
        break;
    }
    case ops_packet_forward_ctl: {//转发控制指令
        forward_ctl(bridge, packet);
        break;
    }
    case ops_packet_forward_data: {//转发数据
        forward_data(bridge, packet, size);
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
    if (bridge->stream) {
        send_buffer* buffer = malloc(sizeof(send_buffer));
        memset(buffer, 0, sizeof(*buffer));
        buffer->data = buf->base;
        buffer->size = buf->len;
        //写入队列
        if (bridge->tail == NULL) {
            bridge->send = buffer;
        }
        else {
            bridge->tail->next = buffer;
        }
        bridge->tail = buffer;
        //
        lsquic_stream_wantwrite(bridge->stream, 1);
    }
    else {
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        if (req == NULL) {
            free(buf->base);
            return;
        }
        req->data = buf->base;
        uv_write(req, &bridge->tcp, &buf, 1, write_cb);
    }
}
//数据到达
static void bridge_on_read(opc_bridge* bridge, char* buf, int len) {
    opc_global* global = bridge->global;
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &global->m_mp, buf, len);
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
    bridge_on_read(bridge, buf->base, nread);
}
//连接返回
static void bridge_on_connect(opc_bridge* bridge) {
    //连接成功
    bridge->global->bridge = obj_ref(bridge);//ref_3

    uv_timer_init(loop, &bridge->keep_timer);
    bridge->keep_timer.data = obj_ref(bridge);//ref_4

    //
    bridge_connect_end(bridge);
}
static void bridge_connect_cb(uv_connect_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    obj_unref(bridge);//ref_2
    free(req);
    if (status < 0) {
        printf("Connect Error %s\r\n", uv_strerror(status));
        //关闭
        uv_close(&bridge->tcp, bridge_close_cb);
        return;
    }
    //
    uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);

    bridge_on_connect(bridge);
}
//
static void bridge_obj_free(opc_bridge* p) {
    //定时重连
    uv_timer_start(&p->global->re_timer, bridge_re_timer_cb, 1000 * 5, 0);
    //
    if (p->global->bridge == p) {
        p->global->bridge = NULL;
    }
}
//启动连接
static int bridge_start_connect(opc_global* global) {
    obj_new(bridge, opc_bridge);//ref_1
    if (bridge == NULL)
        return 0;
    bridge->ref.del = bridge_obj_free;
    bridge->global = global;
    if (global->config.use_quic) {
        //获取本地地址
        struct sockaddr_in6 local = { 0 };
        int namelen = sizeof(local);
        uv_udp_getsockname(&global->quic.udp, &local, &namelen);
        //连接
        struct sockaddr_in6 _addr;
        //
        if (uv_ip6_addr(global->config.server_ip, global->config.server_port, &_addr) < 0) {
            char tmp[1024] = { 0 };
            snprintf(tmp, sizeof(tmp), "::ffff:%s", global->config.server_ip);
            if (uv_ip6_addr(tmp, global->config.server_port, &_addr) < 0) {

            }
        }
        void* ctx = obj_ref(bridge);
        bridge->conn = lsquic_engine_connect(global->quic.engine, N_LSQVER, &local, &_addr, global, ctx, "localhost", 0, NULL, 0, NULL, 0);// global->quic.token, global->quic.token_len);
        quic_process_conns(global);
        return 0;
    }
    uv_connect_t* req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    if (req == NULL) {
        free(req);
        return 0;
    }
    memset(req, 0, sizeof(uv_connect_t));
    req->data = obj_ref(bridge);//ref_2

    uv_tcp_init(loop, &bridge->tcp);
    bridge->tcp.data = obj_ref(bridge);//ref_5

    if (global->config.bind_ip) {
        struct sockaddr_in _bind;
        uv_ip4_addr(global->config.bind_ip, 0, &_bind);
        uv_tcp_bind(&bridge->tcp, &_bind, 0);
    }
    struct sockaddr_in _addr;
    uv_ip4_addr(global->config.server_ip, global->config.server_port, &_addr);
    uv_tcp_connect(req, &bridge->tcp, &_addr, bridge_connect_cb);
    printf("Start Connect\r\n");
    return 0;
}
//重连回调
static void bridge_re_timer_cb(uv_timer_t* handle) {
    opc_global* global = (opc_global*)handle->data;
    bridge_start_connect(global);
}
//----------------------------------------------------------quic
#if HAVE_QUIC
static void quic_timer_cb(uv_timer_t* handle);
static void quic_process_conns(opc_global* global) {
    int diff = 0;
    lsquic_engine_process_conns(global->quic.engine);
    if (lsquic_engine_earliest_adv_tick(global->quic.engine, &diff)) {
        if (diff < 0 || (unsigned)diff < global->quic.engine_settings.es_clock_granularity) {
            uv_timer_start(&global->quic.event, quic_timer_cb, global->quic.engine_settings.es_clock_granularity / 1000, 0);
        }
        else {
            uv_timer_start(&global->quic.event, quic_timer_cb, diff / 1000, 0);
        }
    }
}
static void quic_timer_cb(uv_timer_t* handle) {
    opc_global* global = (opc_global*)handle->data;
    quic_process_conns(global);
}
typedef struct quic_send_t {
    uv_udp_send_t req;
    uv_buf_t* buf;
    int len;
} quic_send_t;
static void quic_send_cb(quic_send_t* req, int status) {
    if (req->buf) {
        for (size_t i = 0; i < req->len; i++) {
            if (req->buf[i].base) {
                free(req->buf[i].base);
            }
        }
        free(req->buf);
    }
    free(req);
}
static int send_packets_out(void* ctx, const struct lsquic_out_spec* specs, unsigned n_specs) {
    opc_global* global = (opc_global*)ctx;
    int n = 0;
    for (n = 0; n < n_specs; ++n) {
        quic_send_t* req = malloc(sizeof(quic_send_t));
        if (!req)
            break;
        req->buf = malloc(sizeof(uv_buf_t) * specs[n].iovlen);
        if (!req->buf) {
            free(req->buf);
            break;
        }
        req->len = specs[n].iovlen;
        for (size_t i = 0; i < specs[n].iovlen; i++) {
            req->buf[i].base = malloc(specs[n].iov[i].iov_len);
            if (req->buf[i].base) {
                req->buf[i].len = specs[n].iov[i].iov_len;
                memcpy(req->buf[i].base, specs[n].iov[i].iov_base, specs[n].iov[i].iov_len);
            }
        }
        if (uv_udp_send(&req->req, &global->quic.udp, req->buf, specs[n].iovlen, specs[n].dest_sa, quic_send_cb) != 0) {
            break;
        }
    }
    return (int)n;
}
static void bridge_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    opc_global* global = (opc_global*)handle->data;
    if (nread) {
        struct sockaddr_in6 local;
        int namelen = sizeof(local);
        uv_udp_getsockname(handle, &local, &namelen);
        lsquic_engine_packet_in(global->quic.engine, buf->base, nread, &local, addr, global, 0);
        quic_process_conns(global);
        free(buf->base);
    }
}
//获取ssl_ctx
static SSL_CTX* get_ssl_ctx(void* peer_ctx, const struct sockaddr* unused) {
    opc_global* global = peer_ctx;
    return global->quic.ssl_ctx;
}
//新连接
static lsquic_conn_ctx_t* quic_on_new_conn(void* stream_if_ctx, lsquic_conn_t* conn) {
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(conn);
    return bridge;
}
//链接关闭
static void quic_on_conn_closed(lsquic_conn_t* conn) {
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(conn);
    bridge->conn = NULL;
    bridge_on_close(bridge);
    lsquic_conn_set_ctx(conn, NULL);
}
//握手完成
static void quic_on_hsk_done(lsquic_conn_t* c, enum lsquic_hsk_status s) {
    //创建流
    lsquic_conn_make_stream(c);
}
static void quic_on_new_token(lsquic_conn_t* c, const unsigned char* token, size_t token_size) {
    opc_global* global = (opc_global*)c;
    if (global->quic.token)
        free(global->quic.token);
    global->quic.token = malloc(token_size);
    memcpy(global->quic.token, token, token_size);
    global->quic.token_len = token_size;
}
//新流
static struct lsquic_stream_ctx* quic_on_new_stream(void* unused, struct lsquic_stream* stream) {
    opc_global* global = (opc_global*)unused;
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    //开始读
    lsquic_stream_wantread(stream, 1);
    //主流
    if (bridge->stream == NULL) {
        bridge->stream = stream;
        bridge_on_connect(bridge);
    }
    return bridge;
}
static size_t quic_readf(void* ctx, const unsigned char* buf, size_t len, int fin) {
    char* tmp = malloc(len);
    memcpy(tmp, buf, len);
    bridge_on_read((opc_bridge*)ctx, (char*)tmp, len);
    return len;
}
static void quic_on_read(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    lsquic_stream_readf(stream, quic_readf, stream_ctx);
}
static void quic_on_write(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    opc_bridge* bridge = (opc_bridge*)stream_ctx;
    if (stream == bridge->stream && bridge->send) {
        send_buffer* buffer = bridge->send;
        do {
            ssize_t ok = lsquic_stream_write(stream, buffer->data + buffer->pos, buffer->size - buffer->pos);
            if (ok < 0) {
                break;
            }
            //本次写完
            if (ok == buffer->size - buffer->pos) {
                free(buffer->data);
                send_buffer* temp = buffer;
                buffer = buffer->next;
                bridge->send = buffer;
                free(temp);
                //队列写完
                if (buffer == NULL) {
                    bridge->send = NULL;
                    bridge->tail = NULL;
                    lsquic_stream_wantwrite(stream, 0);
                    break;
                }
            }
            else {
                //没写完,等下一次发送
                buffer->pos += ok;
                break;
            }
        } while (buffer != NULL);
    }
    lsquic_stream_flush(stream);
}
//流关闭
static void quic_on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* stream_ctx) {
    opc_bridge* bridge = (opc_bridge*)stream_ctx;
    if (bridge->stream == stream) {
        bridge->stream = NULL;
    }
}

static void bridge_init_quic(opc_global* global) {
    struct sockaddr_in6 _addr;
    lsquic_global_init(LSQUIC_GLOBAL_CLIENT);

    //lsquic_set_log_level("DEBUG");
    //lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);

    lsquic_engine_init_settings(&global->quic.engine_settings, 0);

    global->quic.stream_if.on_new_conn = quic_on_new_conn;
    global->quic.stream_if.on_conn_closed = quic_on_conn_closed;
    global->quic.stream_if.on_new_stream = quic_on_new_stream;
    global->quic.stream_if.on_read = quic_on_read;
    global->quic.stream_if.on_write = quic_on_write;
    global->quic.stream_if.on_close = quic_on_close;
    global->quic.stream_if.on_hsk_done = quic_on_hsk_done;
    global->quic.stream_if.on_new_token = quic_on_new_token;

    global->quic.engine_api.ea_settings = &global->quic.engine_settings;
    global->quic.engine_api.ea_stream_if = &global->quic.stream_if;
    global->quic.engine_api.ea_stream_if_ctx = global;
    global->quic.engine_api.ea_packets_out = send_packets_out;
    global->quic.engine_api.ea_packets_out_ctx = global;
    global->quic.engine_api.ea_cert_lu_ctx = global;
    global->quic.engine_api.ea_get_ssl_ctx = &get_ssl_ctx;

    char err_buf[100];
    if (0 != lsquic_engine_check_settings(global->quic.engine_api.ea_settings, 0, err_buf, sizeof(err_buf))) {
        return;
    }

    global->quic.engine = lsquic_engine_new(0, &global->quic.engine_api);

    //SSL
    global->quic.ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    //设置ALPN
    SSL_CTX_set_alpn_protos(global->quic.ssl_ctx, "\x04quic", 5);

    //事件定时器
    uv_timer_init(loop, &global->quic.event);
    global->quic.event.data = global;

    //监听udp端口
    uv_udp_init(loop, &global->quic.udp);
    global->quic.udp.data = global;
    //指定了本地端口
    if (global->config.bind_ip) {

    }
    else {
        uv_ip6_addr("::0", 0, &_addr);
    }
    uv_udp_bind(&global->quic.udp, &_addr, 0);
    uv_udp_recv_start(&global->quic.udp, alloc_buffer, bridge_udp_recv_cb);
}

#endif
//--------------------------------------------------------------------------------------------------------
//全局初始化
static int init_global(opc_global* global) {
    uv_timer_init(loop, &global->re_timer);
    global->re_timer.data = global;


#if HAVE_QUIC
    bridge_init_quic(global);
#endif

}
//主流程
static opc_global* global = NULL;

static void obj_check(uv_timer_t* handle) {
    obj_print();
}

static int run() {
    //初始化
    init_global(global);
    //开始连接
    bridge_start_connect(global);
#ifdef _DEBUG
    //启动定时器
    uv_timer_t timer;
    uv_timer_init(loop, &timer);
    uv_timer_start(&timer, obj_check, 5000, 5000);
#endif
    //启动循环
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
//win系统服务
#if defined(_WIN32) || defined(_WIN64)
static int run();
int install_service = 0;
int run_service = 0;
char* szServiceName = NULL;
SERVICE_STATUS status;
SERVICE_STATUS_HANDLE hServiceStatus;

void WINAPI ServiceStrl(DWORD dwOpcode) {
    switch (dwOpcode)
    {
    case SERVICE_CONTROL_STOP:
        status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hServiceStatus, &status);
        //结束服务
        ExitProcess(0);
        break;
    case SERVICE_CONTROL_PAUSE:
        break;
    case SERVICE_CONTROL_CONTINUE:
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        break;
    default:
        //LogEvent(_T("Bad service request"));
        break;
    }
}
void WINAPI ServiceMain() {
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    //注册服务控制  
    hServiceStatus = RegisterServiceCtrlHandler(szServiceName, ServiceStrl);
    if (hServiceStatus == NULL) {
        //LogEvent("Handler not installed");
        return;
    }
    SetServiceStatus(hServiceStatus, &status);

    status.dwWin32ExitCode = S_OK;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServiceStatus, &status);

    run();

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hServiceStatus, &status);
    //LogEvent("Service stopped");
}
//判断服务是否安装
BOOL IsInstalled() {
    BOOL bResult = FALSE;

    //打开服务控制管理器  
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM != NULL) {
        //打开服务  
        SC_HANDLE hService = OpenService(hSCM, szServiceName, SERVICE_QUERY_CONFIG);
        if (hService != NULL) {
            bResult = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
    return bResult;
}
BOOL Uninstall() {
    if (!IsInstalled(szServiceName))
        return TRUE;

    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hSCM == NULL) {
        MessageBox(NULL, "Couldn't open service manager", szServiceName, MB_OK);
        return FALSE;
    }

    SC_HANDLE hService = OpenService(hSCM, szServiceName, SERVICE_STOP | DELETE);

    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        MessageBox(NULL, "Couldn't open service", szServiceName, MB_OK);
        return FALSE;
    }
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    //删除服务  
    BOOL bDelete = DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (bDelete)
        return TRUE;
    return FALSE;
}
BOOL Install(int argc, char* argv[]) {
    if (IsInstalled(szServiceName)) {
        return TRUE;
    }
    //打开服务控制管理器  
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        MessageBox(NULL, "Couldn't open service manager", szServiceName, MB_OK);
        return FALSE;
    }

    // Get the executable file path  
    TCHAR szFilePath[MAX_PATH];
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    TCHAR szCmd[512] = { 0 };
    strcat(szCmd, szFilePath);
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-install") == 0) {
            strcat(szCmd, " -service ");
            i++;
            strcat(szCmd, argv[i]);
        }
        else {
            strcat(szCmd, " ");
            strcat(szCmd, argv[i]);
            i++;
            strcat(szCmd, " ");
            strcat(szCmd, argv[i]);
        }
    }

    //创建服务  
    SC_HANDLE hService = CreateService(
        hSCM, szServiceName, szServiceName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        szCmd, NULL, NULL, "", NULL, NULL);

    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        MessageBox(NULL, "Couldn't create service", szServiceName, MB_OK);
        return FALSE;
    }

    StartService(hService, 0, NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}
#endif
//安卓
#ifdef __ANDROID__
#include <jni.h>

uv_thread_t* android_tid = NULL;

static void android_thr(void* arg) {
    loop = uv_default_loop();
    global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return;
    memset(global, 0, sizeof(*global));

    run();
}



jint JNICALL Java_org_ops_client_MainActivity_init(JNIEnv* env, jobject* this) {
    char* str = "Hello from C++";
    if (android_tid) {
        return -1;
    }
    android_tid = (uv_thread_t*)malloc(sizeof(*android_tid));
    if (uv_thread_create(android_tid, android_thr, NULL) == 0) {
        return 0;
    }
    return -2;
}
#else
//加载配置
static int load_config(opc_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.server_ip = "127.0.0.1";
    global->config.server_port = 8025;
    global->config.use_quic = 1;

    //从配置文件加载参数
    const char* config_file = "opc.json";
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            i++;
            config_file = argv[i];
            break;
        }
    }
    FILE* config_fd = fopen(config_file, "r");
    cJSON* config_json = NULL;
    if (config_fd) {
        fseek(config_fd, 0, SEEK_END);
        long size = ftell(config_fd);
        fseek(config_fd, 0, SEEK_SET);
        char* data = (char*)malloc(size + 1);
        fread(data, 1, size, config_fd);
        data[size] = '\0';
        config_json = cJSON_Parse(data);
        fclose(config_fd);
        free(data);
    }
    if (config_json) {
        cJSON* item = cJSON_GetObjectItem(config_json, "server_ip");
        if (item && item->valuestring) {
            global->config.server_ip = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "server_port");
        if (item && item->valueint) {
            global->config.server_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "auth_key");
        if (item && item->valuestring) {
            global->config.auth_key = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "bind_ip");
        if (item && item->valuestring) {
            global->config.bind_ip = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "quic");
        if (item && item->valuestring) {
            global->config.use_quic = item->valueint;
        }
        cJSON_free(config_json);
    }
    //从命令行加载参数
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            i++;
            global->config.server_ip = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-b") == 0) {
            i++;
            global->config.bind_ip = strdup(argv[i]);
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
        else if (strcmp(argv[i], "-q") == 0) {
            global->config.use_quic = 1;
        }
#if defined(_WIN32) || defined(_WIN64)
        else if (strcmp(argv[i], "-install") == 0) {
            i++;
            szServiceName = argv[i];
            install_service = 1;
        }
        else if (strcmp(argv[i], "-uninstall") == 0) {
            i++;
            szServiceName = argv[i];
            install_service = -1;
        }
        else if (strcmp(argv[i], "-service") == 0) {
            i++;
            szServiceName = argv[i];
            run_service = 1;
        }
#endif
    }
    return 0;
}

int main(int argc, char* argv[]) {
    loop = uv_default_loop();
    global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //加载参数
    load_config(global, argc, argv);
#if defined(_WIN32) || defined(_WIN64)
    if (install_service == 1) {
        Install(argc, argv);
        return 0;
    }
    if (install_service == -1) {
        Uninstall();
        return 0;
    }
    if (run_service) {
        //初始化
        hServiceStatus = NULL;
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        status.dwWin32ExitCode = 0;
        status.dwServiceSpecificExitCode = 0;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        SERVICE_TABLE_ENTRY st[] = {
            { szServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
            { NULL, NULL }
        };
        if (!StartServiceCtrlDispatcher(st)) {
            return 1;
        }
        return 0;
    }
#endif
    run();
    return 0;
}
#endif
