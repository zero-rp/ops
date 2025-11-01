#include <stdint.h>
#include <uv.h>
#include <uv/tree.h>
#include <common/obj.h>
#include <common/common.h>
#include "forward.h"

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
    struct _module_forward* mod;
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
    struct _module_forward* mod;
}opc_forward;
RB_HEAD(_opc_forward_tree, _opc_forward);
//模块
typedef struct _module_forward {
    opc_module mod;
    obj_field ref;                                        //计数
    opc_bridge* bridge;
    uint32_t tunnel_id;                         //转发流ID分配
    struct _opc_forward_tunnel_tree forward_tunnel;     //
    struct _opc_forward_tree forward;
}module_forward;

static int _opc_forward_tunnel_compare(opc_forward_tunnel* w1, opc_forward_tunnel* w2) {
    if (w1->stream_id < w2->stream_id) return -1;
    if (w1->stream_id > w2->stream_id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tunnel_tree, _opc_forward_tunnel, entry, _opc_forward_tunnel_compare)
static int _opc_forward_compare(opc_forward* w1, opc_forward* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_forward_tree, _opc_forward, entry, _opc_forward_compare)

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
//--------------------------隧道
static void forward_tunnel_free(opc_forward_tunnel* p) {
    RB_REMOVE(_opc_forward_tunnel_tree, &p->mod->forward_tunnel, p);
    obj_unref(p->mod);//ref_12
    obj_unref(p->src);//ref_11
}
//失败关闭对端隧道
static void forward_tunnel_err(opc_bridge* bridge, uint32_t service_id, uint32_t stream_id) {
    uint8_t buf[1];
    buf[0] = CTL_FORWARD_CTL_ERR;//连接失败
    bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
}
//来源连接关闭
static void forward_tunnel_close_cb(uv_handle_t* handle) {
    opc_forward_tunnel* tunnel = (opc_forward_tunnel*)handle->data;
    forward_tunnel_err(tunnel->mod->bridge, tunnel->src->id, tunnel->pree_id);
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
    uv_write(req, (uv_stream_t*)&tunnel->tcp, buf, 1, write_cb);
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
                    bridge_send_mod(tunnel->mod->bridge, MODULE_FORWARD, forward_packet_ctl, tunnel->src->id, tunnel->stream_id, buf, sizeof(buf));
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
        bridge_send_mod(tunnel->mod->bridge, MODULE_FORWARD, forward_packet_data, tunnel->src->id, tunnel->pree_id, buf->base, nread);
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
    tunnel->ref.del = (obj_del)forward_tunnel_free;

    uv_tcp_init(bridge_loop(src->mod->bridge), &tunnel->tcp);//初始化tcp bridge句柄
    tunnel->tcp.data = obj_ref(tunnel);//ref_8

    if (uv_accept(tcp, (uv_stream_t*)&tunnel->tcp) == 0) {
        //记录
        tunnel->mod = obj_ref(src->mod);//ref_12
        tunnel->src = obj_ref(src);//ref_11
        tunnel->stream_id = tunnel->mod->tunnel_id++;
        RB_INSERT(_opc_forward_tunnel_tree, &src->mod->forward_tunnel, tunnel);
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
            bridge_send_mod(src->mod->bridge, MODULE_FORWARD, forward_packet_ctl, src->id, tunnel->stream_id, buf, sizeof(buf));
        }
    }
    else {
        obj_unref(tunnel);//ref_8
        obj_unref(tunnel);//ref_7
    }
}
static void forward_obj_free(opc_forward* p) {
    RB_REMOVE(_opc_forward_tree, &p->mod->forward, p);
    obj_unref(p->mod);//ref_6
}
//转发源监听关闭
static void forward_close_cb(uv_handle_t* handle) {
    opc_forward* src = (opc_forward*)handle->data;
    obj_unref(src);//ref_10
    obj_unref(src);//ref_9
}
//新转发源
static int forward_new(module_forward* mod, ops_forward* src) {
    obj_new(s, opc_forward);//ref_9
    if (!s) {
        return -1;
    }
    s->ref.del = (obj_del)forward_obj_free;
    s->id = src->sid;
    s->type = src->type;
    s->mod = obj_ref(mod);//ref_6
    switch (s->type)
    {
    case FORWARD_TYPE_TCP:
    case FORWARD_TYPE_SOCKS5:
    case FORWARD_TYPE_HTTP: {
        uv_tcp_init(bridge_loop(mod->bridge), &s->tcp.tcp);
        s->tcp.tcp.data = obj_ref(s);//ref_10
        //绑定
        struct sockaddr_in6 _addr;
        uv_ip6_addr("::0", src->port, &_addr);
        uv_tcp_bind(&s->tcp.tcp, (const struct sockaddr*)&_addr, 0);
        //允许复用
        uv_os_fd_t fd;
        if (uv_fileno((uv_handle_t*)&s->tcp.tcp, &fd) == 0) {
            int val = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        }
        //监听端口
        uv_listen((uv_stream_t*)&s->tcp.tcp, 32, forward_connection_cb);
    }
    case FORWARD_TYPE_UDP: {


        break;
    }
    default:
        break;
    }
    RB_INSERT(_opc_forward_tree, &mod->forward, s);
    return 0;
}
//-----------------------------------------------------服务器控制回调
static void _forward(module_forward* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    uint8_t ctl = data[0];
    char* pos = &data[1];
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

            if (forward_new(mod, &src) == 0) {
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
static void _ctl(module_forward* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    opc_forward_tunnel the = {
        .stream_id = stream_id
    };
    opc_forward_tunnel* tunnel = RB_FIND(_opc_forward_tunnel_tree, &mod->forward_tunnel, &the);
    if (!tunnel) {
        //连接已经不存在了,丢弃
        return;
    }
    switch (data[0])
    {
    case CTL_FORWARD_CTL_SUC: {
        //读取对端流ID
        tunnel->pree_id = ntohl(*(uint32_t*)(&data[1]));
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
static void _data(module_forward* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    opc_forward_tunnel  the = {
        .stream_id = stream_id
    };
    opc_forward_tunnel* tunnel = RB_FIND(_opc_forward_tunnel_tree, &mod->forward_tunnel, &the);
    if (!tunnel)
        return;
    //转发数据到本地
    forward_tunnel_send(tunnel, data, size);
}

//处理数据
static void forward_data(module_forward* mod, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case forward_packet_forward:
        _forward(mod, stream_id, service_id, data, size);
        break;
    case forward_packet_ctl:
        _ctl(mod, stream_id, service_id, data, size);
        break;
    case forward_packet_data:
        _data(mod, stream_id, service_id, data, size);
        break;
    default:
        break;
    }
}
//回收对象
static void module_forward_obj_free(module_forward* mod) {
    bridge_unref(mod->bridge);
}
//创建转发模块
module_forward* forward_module_new(opc_bridge* bridge) {
    obj_new(mod, module_forward);
    if (!mod) {
        return NULL;
    }
    mod->ref.del = (obj_del)module_forward_obj_free;
    mod->bridge = bridge_ref(bridge);
    mod->mod.on_data = (opc_module_on_data)forward_data;
    mod->tunnel_id = 1;
    RB_INIT(&mod->forward_tunnel);
    RB_INIT(&mod->forward);
    return mod;
}
//回收资源
void forward_module_delete(module_forward* mod) {
    //关闭源隧道
    opc_forward_tunnel* sc = NULL;
    opc_forward_tunnel* scc = NULL;
    RB_FOREACH_SAFE(sc, _opc_forward_tunnel_tree, &mod->forward_tunnel, scc) {
        forward_tunnel_shutdown(sc);
        sc = NULL;
    }
    //关闭源
    opc_forward* fsc = NULL;
    opc_forward* fscc = NULL;
    RB_FOREACH_SAFE(fsc, _opc_forward_tree, &mod->forward, fscc) {
        uv_close((uv_handle_t*)&fsc->tcp, forward_close_cb);
        fsc = NULL;
    }
    obj_unref(mod);
}
