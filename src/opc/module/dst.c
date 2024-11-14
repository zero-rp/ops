#include <stdlib.h>
#include <stdint.h>
#include <uv.h>
#include <uv/tree.h>
#include <common/obj.h>
#include "dst.h"

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
    struct _module_dst* mod;
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

//模块
typedef struct _module_dst {
    opc_module mod;
    obj_field ref;                                        //计数
    opc_bridge* bridge;
    uint32_t tunnel_id;                         //转发流ID分配
    struct _opc_dst_tunnel_tree dst_tunnel;     //
    struct _opc_dst_tree dst;
}module_dst;


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

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}

//--------------------------隧道
static void dst_tunnel_free(opc_dst_tunnel* p) {
    RB_REMOVE(_opc_dst_tunnel_tree, &p->mod->dst_tunnel, p);
    obj_unref(p->dst);//ref_16
    obj_unref(p->mod);//ref_17
}
//失败关闭对端隧道
static void dst_tunnel_err(module_dst* mod, uint32_t service_id, uint32_t stream_id) {
    uint8_t buf[1];
    buf[0] = CTL_DST_CTL_ERR;//连接失败
    bridge_send_mod(mod->bridge, MODULE_DST, dst_packet_ctl, service_id, stream_id, buf, sizeof(buf));
}
//目标连接关闭
static void dst_tunnel_close_cb(uv_handle_t* handle) {
    opc_dst_tunnel* tunnel = (opc_dst_tunnel*)handle->data;
    dst_tunnel_err(tunnel->mod, tunnel->dst->id, tunnel->pree_id);
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
    bridge_send_mod(tunnel->mod->bridge, MODULE_DST, dst_packet_data, tunnel->dst->id, tunnel->pree_id, buf->base, nread);
    free(buf->base);
}
//连接返回
static void dst_tunnel_connect_cb(uv_connect_t* req, int status) {
    opc_dst_tunnel* tunnel = req->data;
    obj_unref(tunnel);//ref_19
    if (status < 0) {
        //连接失败
        dst_tunnel_err(tunnel->mod, tunnel->dst->id, tunnel->pree_id);
        //关闭连接
        uv_close((uv_handle_t*)&tunnel->tcp, dst_tunnel_close_cb);
        return;
    }
    //通知成功
    uint8_t buf[5];
    buf[0] = CTL_DST_CTL_SUC;//连接成功
    *(uint32_t*)(&buf[1]) = htonl(tunnel->stream_id);
    bridge_send_mod(tunnel->mod->bridge, MODULE_DST, dst_packet_ctl, tunnel->dst->id, tunnel->pree_id, buf, sizeof(buf));
    //连接远端成功
    uv_read_start((uv_stream_t*)&tunnel->tcp, alloc_buffer, dst_tunnel_read_cb);
}
//转发隧道解析目标主机
static void dst_tunnel_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    opc_dst_tunnel* tunnel = req->data;
    obj_unref(tunnel);//ref_15
    if (status != 0) {
        //通知失败
        dst_tunnel_err(tunnel->mod, tunnel->dst->id, tunnel->pree_id);
        printf("No DNS Forward Id %d\r\n", tunnel->dst->id);
        return;
    }
    uv_tcp_init(bridge_loop(tunnel->mod->bridge), &tunnel->tcp);
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
        dst_tunnel_err(tunnel->mod, tunnel->dst->id, tunnel->pree_id);
    }
    //释放结果
    uv_freeaddrinfo(res);
}
//新目标隧道
static opc_dst_tunnel* dst_tunnel_new(module_dst* mod, opc_dst* dst, uint32_t pree_id, uint8_t* data, int size) {
    obj_new(tunnel, opc_dst_tunnel);//ref_14
    if (!tunnel)
        return NULL;
    tunnel->ref.del = dst_tunnel_free;

    tunnel->dst = obj_ref(dst);//ref_16
    tunnel->mod = obj_ref(mod);//ref_17

    tunnel->stream_id = mod->tunnel_id++;
    tunnel->pree_id = pree_id;
    RB_INSERT(_opc_dst_tunnel_tree, &mod->dst_tunnel, tunnel);
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
        uv_getaddrinfo(bridge_loop(tunnel->mod->bridge), &tunnel->req_info, dst_tunnel_getaddrinfo_cb, addr, buf, NULL);
    }
    else {
        char buf[10] = { 0 };
        snprintf(buf, sizeof(buf), "%d", dst->port);
        uv_getaddrinfo(bridge_loop(tunnel->mod->bridge), &tunnel->req_info, dst_tunnel_getaddrinfo_cb, dst->dst, buf, NULL);
    }
    return tunnel;
}
//--------------------------目标
//新转发目标
static int dst_new(module_dst* mod, ops_dst* dst) {
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

    RB_INSERT(_opc_dst_tree, &mod->dst, d);
    return 0;
}
//删除转发目标
static void dst_del(module_dst* mod, opc_dst* dst) {
    RB_REMOVE(_opc_dst_tree, &mod->dst, dst);
    obj_unref(dst);//ref_23
}
//-----------------------------------------------------服务器控制回调
static void _dst(module_dst* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    uint8_t ctl = data[0];
    char* pos = &data[1];
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
            if (dst_new(mod, &dst) == 0) {
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
static void _ctl(module_dst* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    uint8_t type = data[0];
    switch (type)
    {
    case CTL_DST_CTL_OPEN: {//发起请求
        //查找目标服务
        printf("New DST Request For Id %d\r\n", service_id);
        opc_dst ths = {
            .id = service_id
        };
        opc_dst* dst = RB_FIND(_opc_dst_tree, &mod->dst, &ths);
        if (dst == NULL) {
            printf("No Find Forward Id %d\r\n", service_id);
            dst_tunnel_err(mod, service_id, stream_id);
            break;
        }
        //请求连接远端
        opc_dst_tunnel* tunnel = dst_tunnel_new(mod, dst, stream_id, size > 1 ? &data[1] : NULL, size - 1);
        if (!tunnel) {
            dst_tunnel_err(mod, service_id, stream_id);
            break;
        }
        break;
    }
    case CTL_DST_CTL_ERR: { //异常
        opc_dst_tunnel the = {
            .stream_id = stream_id
        };
        opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &mod->dst_tunnel, &the);
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
            .stream_id = stream_id
        };
        opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &mod->dst_tunnel, &the);
        if (!tunnel) {
            //连接已经不存在了,丢弃
            break;
        }
        if (data[1] == 0x01) {
            //来源方向异常
            dst_tunnel_shutdown(tunnel);
        }
        break;
    }
    default:
        break;
    }
}
static void _data(module_dst* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    opc_dst_tunnel  the = {
        .stream_id = stream_id
    };
    opc_dst_tunnel* tunnel = RB_FIND(_opc_dst_tunnel_tree, &mod->dst_tunnel, &the);
    if (!tunnel)
        return;
    //转发数据到远程
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
    uv_write(req, (uv_stream_t*)&tunnel->tcp, &buf, 1, write_cb);
}

//处理数据
static void dst_data(module_dst* mod, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case dst_packet_dst:
        _dst(mod, stream_id, service_id, data, size);
        break;
    case dst_packet_ctl:
        _ctl(mod, stream_id, service_id, data, size);
        break;
    case dst_packet_data:
        _data(mod, stream_id, service_id, data, size);
        break;
    default:
        break;
    }
}

//创建目标模块
module_dst* dst_module_new(opc_bridge* bridge) {
    obj_new(mod, module_dst);
    if (!mod) {
        return NULL;
    }
    mod->bridge = bridge_ref(bridge);
    mod->mod.on_data = (opc_module_on_data)dst_data;
    RB_INIT(&mod->dst_tunnel);
    RB_INIT(&mod->dst);
    mod->tunnel_id = 1;
    return mod;
}
//回收资源
void dst_module_delete(module_dst* mod) {
    //关闭目标隧道
    opc_dst_tunnel* dc = NULL;
    opc_dst_tunnel* dcc = NULL;
    RB_FOREACH_SAFE(dc, _opc_dst_tunnel_tree, &mod->dst_tunnel, dcc) {
        dst_tunnel_shutdown(dc);
        dc = NULL;
    }
    //关闭目标
    opc_dst* fdc = NULL;
    opc_dst* fdcc = NULL;
    RB_FOREACH_SAFE(fdc, _opc_dst_tree, &mod->dst, fdcc) {
        dst_del(mod, fdc);
        fdc = NULL;
    }

}
