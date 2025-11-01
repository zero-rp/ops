#include <uv.h>
#include <common/common.h>
#include <common/obj.h>
#include <common/databuffer.h>
#if HAVE_QUIC
#include <lsquic.h>
#endif
#include "bridge.h"
#include "module/forward.h"
#include "module/dst.h"
#include "module/vpc.h"

typedef struct _send_buffer {
    uint8_t* data;
    uint32_t size;
    uint32_t pos;
    struct _send_buffer* next;
}send_buffer;

//网桥
typedef struct _opc_bridge {
    obj_field ref;                                      //计数
    uv_loop_t* loop;
    uv_tcp_t tcp;                                       //服务器通讯句柄
#if HAVE_QUIC
    lsquic_conn_t* conn;
    lsquic_stream_t* stream;                            //quic
#endif
    send_buffer* send;                                  //发送缓冲
    send_buffer* tail;                                  //发送缓冲尾
    struct _opc_global* global;
    struct databuffer m_buffer;                         //接收缓冲
    struct messagepool m_mp;                            //接收缓冲
    uv_timer_t keep_timer;                              //心跳,重鉴权定时器
    uint64_t keep_last;                                 //上次心跳
    uint32_t keep_ping;                                 //延迟
    struct {
        uint8_t quit : 1;                               //当前连接已退出
        uint8_t connect : 1;                            //已连接
    } b;
    opc_module* modules[256];             //模块
}opc_bridge;

static void quic_process_conns(opc_global* global);

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}

//检查是否退出
static void bridge_check() {

}
//鉴权成功
static void bridge_auth_ok(opc_bridge* bridge) {
    //提交设备信息


}
//发送鉴权数据
static void bridge_auth_send(opc_bridge* bridge) {
    int size = strlen(opc_get_config(bridge->global)->auth_key) + 3;
    char* buf = malloc(size);
    if (buf == NULL)
        return;
    *(uint16_t*)(buf) = htons(size - 2);
    strcpy(buf + 2, opc_get_config(bridge->global)->auth_key);
    bridge_send_auth(bridge, buf, size);
    free(buf);
}
//成功连接上服务器
static void bridge_connect_ok(opc_bridge* bridge) {
    bridge->b.connect = 1;
    //启动心跳
    uv_timer_init(bridge->loop, &bridge->keep_timer);
    bridge->keep_timer.data = obj_ref(bridge);//ref_4
    //发送鉴权数据
    bridge_auth_send(bridge);
}
//
static void bridge_keep_close_cb(uv_handle_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    obj_unref(bridge);//ref_4
}
//关闭
static void bridge_on_close(opc_bridge* bridge) {
    bridge->b.quit = 1;
    //回收资源
    databuffer_clear(&bridge->m_buffer, &bridge->m_mp);
    //回收目标
    dst_module_delete((module_dst*)bridge->modules[MODULE_DST]);
    //回收转发器
    forward_module_delete((module_forward*)bridge->modules[MODULE_FORWARD]);
    //回收vpc
    vpc_module_delete((module_vpc*)bridge->modules[MODULE_VPC]);
    //关闭定时器
    if (bridge->keep_timer.data) {
        uv_close((uv_handle_t*)&bridge->keep_timer, bridge_keep_close_cb);
    }
    //触发
    opc_on_close(bridge->global);
}
//ping检测定时器
static void bridge_close_cb(uv_handle_t* handle);
static void bridge_keep_timer_cb(uv_timer_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    //检查是否超时
    uv_timespec64_t now;
    uv_clock_gettime(UV_CLOCK_REALTIME, &now);
    if (bridge->keep_last < (now.tv_sec - 60)) {
        //暂停掉定时器
        uv_timer_stop(handle);
        //超时直接关闭
        //if (bridge->global->config.use_quic) {
        //    if (bridge->conn) {
        //        lsquic_conn_close(bridge->conn);
        //    }
        //}
        //else {
        uv_close((uv_handle_t*)&bridge->tcp, bridge_close_cb);
        //}
        return;
    }
    //
    uint8_t tmp[12];
    *(uint64_t*)&tmp[0] = uv_hrtime();
    *(uint32_t*)&tmp[8] = htonl(bridge->keep_ping);
    //发送ping
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + sizeof(tmp);
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = ops_packet_ping;
    memcpy(pack->data, tmp, sizeof(tmp));
    bridge_send_raw(bridge, buf);
}
//重鉴权定时器
static void bridge_auth_timer_cb(uv_timer_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    bridge_auth_send(bridge);
}
//收到服务端来的数据
static void bridge_on_data(opc_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
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
            uv_timespec64_t now;
            uv_clock_gettime(UV_CLOCK_REALTIME, &now);
            bridge->keep_last = now.tv_sec;
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
        uv_timespec64_t now;
        uv_clock_gettime(UV_CLOCK_REALTIME, &now);
        bridge->keep_last = now.tv_sec;
        bridge->keep_ping = (uv_hrtime() - t) / 1000000;
        break;
    }
    case ops_packet_mod: {
        packet->mod.service_id = ntohl(packet->mod.service_id);
        packet->mod.stream_id = ntohl(packet->mod.stream_id);
        bridge->modules[packet->mod.mod]->on_data(bridge->modules[packet->mod.mod], packet->mod.type, packet->mod.stream_id, packet->mod.service_id, packet->mod.data, size);
        break;
    }
    default:
        break;
    }
}
//向服务器发送数据
void bridge_send_raw(opc_bridge* bridge, uv_buf_t* buf) {
    if (bridge->b.quit || bridge->b.connect == 0) {
        free(buf->base);
        return;
    }
#if HAVE_QUIC
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
        return;
    }
#endif
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, (uv_stream_t*)&bridge->tcp, buf, 1, write_cb);
}
//向服务器发送数据
void bridge_send_mod(opc_bridge* bridge, uint8_t mod, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len) {
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + len;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = ops_packet_mod;
    pack->mod.mod = mod;
    pack->mod.type = type;
    pack->mod.service_id = htonl(service_id);
    pack->mod.stream_id = htonl(stream_id);
    if (data && len) {
        memcpy(pack->mod.data, data, len);
    }
    bridge_send_raw(bridge, buf);
}
void bridge_send_auth(opc_bridge* bridge, const char* data, uint32_t len) {
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + len;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = ops_packet_auth;
    if (data && len) {
        memcpy(pack->data, data, len);
    }
    bridge_send_raw(bridge, buf);
}
//数据到达
static void bridge_on_read(opc_bridge* bridge, char* buf, int len) {
    opc_global* global = bridge->global;
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &bridge->m_mp, buf, len);
    for (;;) {
        int size = databuffer_readheader(&bridge->m_buffer, &bridge->m_mp, 4);
        if (size < 0) {
            return;
        }
        char* temp = malloc(size);
        databuffer_read(&bridge->m_buffer, &bridge->m_mp, temp, size);
        bridge_on_data(bridge, temp, size);
        databuffer_reset(&bridge->m_buffer);
    }
}
#if HAVE_QUIC
static int bridge_connect_quic(opc_bridge* bridge) {
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
#endif
//tcp处理
static void bridge_close_cb(uv_handle_t* handle) {
    opc_bridge* bridge = (opc_bridge*)handle->data;
    //tcp对象引用
    obj_unref(bridge);//ref_5
    //
    bridge_on_close(bridge);
}
static void bridge_shutdown_cb(uv_shutdown_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    uv_close((uv_handle_t*)&bridge->tcp, bridge_close_cb);
    free(req);
}
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    opc_bridge* bridge = (opc_bridge*)tcp->data;
    opc_global* global = bridge->global;
    if (nread <= 0) {
        printf("Server Disconnected\r\n");
        bridge->b.connect = 0;
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close((uv_handle_t*)tcp, bridge_close_cb);
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
                uv_close((uv_handle_t*)tcp, bridge_close_cb);
            }
        }
        return;
    }
    //收到数据
    bridge_on_read(bridge, buf->base, nread);
}
static void bridge_connect_cb(uv_connect_t* req, int status) {
    opc_bridge* bridge = (opc_bridge*)req->data;
    obj_unref(bridge);//ref_2
    free(req);
    if (status < 0) {
        printf("Connect Error %s\r\n", uv_strerror(status));
        //关闭
        uv_close((uv_handle_t*)&bridge->tcp, bridge_close_cb);
        return;
    }
    //开始接收数据
    uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);

    bridge_connect_ok(bridge);
}
static int bridge_connect_tcp(opc_bridge* bridge) {
    uv_connect_t* req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    if (req == NULL) {
        free(req);
        return -1;
    }
    memset(req, 0, sizeof(uv_connect_t));
    req->data = obj_ref(bridge);//ref_2

    uv_tcp_init(bridge->loop, &bridge->tcp);
    bridge->tcp.data = obj_ref(bridge);//ref_5

    if (opc_get_config(bridge->global)->bind_ip) {
        struct sockaddr_in _bind;
        uv_ip4_addr(opc_get_config(bridge->global)->bind_ip, 0, &_bind);
        uv_tcp_bind(&bridge->tcp, (const struct sockaddr*)&_bind, 0);
    }
    struct sockaddr_in _addr;
    uv_ip4_addr(opc_get_config(bridge->global)->server_ip, opc_get_config(bridge->global)->server_port, &_addr);
    uv_tcp_connect(req, &bridge->tcp, (const struct sockaddr*)&_addr, bridge_connect_cb);
    printf("Start Connect\r\n");
    return 0;
}
//连接服务器
int bridge_connect(opc_bridge* bridge) {
#if HAVE_QUIC
    if (opc_get_config(bridge->global)->use_quic) {
        return bridge_connect_quic(bridge);
    }
#endif
    return bridge_connect_tcp(bridge);
}
//回收对象
static void bridge_obj_free(opc_bridge* p) {

}
//创建对象
opc_bridge* bridge_new(opc_global* global) {
    obj_new(bridge, opc_bridge);//ref_1
    if (bridge == NULL)
        return 0;
    bridge->ref.del = (obj_del)bridge_obj_free;
    bridge->global = global;
    bridge->loop = opc_get_loop(global);
    //创建模块
    bridge->modules[MODULE_FORWARD] = (opc_module*)forward_module_new(bridge);
    bridge->modules[MODULE_DST] = (opc_module*)dst_module_new(bridge);
    bridge->modules[MODULE_VPC] = (opc_module*)vpc_module_new(bridge);

    return bridge;
}
//释放对象
void bridge_delete(opc_bridge* bridge) {
    obj_unref(bridge);//ref_1
}
//引用
opc_bridge* bridge_ref(opc_bridge* bridge) {
    obj_ref(bridge);
    return bridge;
}
//解引用
void bridge_unref(opc_bridge* bridge) {
    obj_unref(bridge);
}
//
uv_loop_t* bridge_loop(opc_bridge* bridge) {
    return bridge->loop;
}