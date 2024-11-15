#include <uv.h>
#include <uv/tree.h>
#include <common/common.h>
#include <common/databuffer.h>
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
//授权信息
typedef struct _ops_key {
    RB_ENTRY(_ops_key) entry;          //
    const char* key;                    //
    uint16_t id;                        //客户端ID
}ops_key;
RB_HEAD(_ops_key_tree, _ops_key);
//客户端
typedef struct _ops_bridge {
    RB_ENTRY(_ops_bridge) entry;        //
    uint16_t id;                        //客户端ID
    struct _ops_bridge_manager* manager;    //管理器
    uv_tcp_t tcp;                       //连接
#if HAVE_QUIC
    lsquic_stream_t* stream;                       //quic
    lsquic_conn_t* conn;
    int type;
#endif
    send_buffer* send;                  //发送缓冲
    send_buffer* tail;                  //发送缓冲尾
    struct databuffer m_buffer;         //接收缓冲
    uint32_t ping;                      //延迟
    uint64_t last_ping;                 //上次
    struct {
        uint8_t quit : 1;                               //当前连接已退出
    } b;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } peer;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local;
}ops_bridge;
RB_HEAD(_ops_bridge_tree, _ops_bridge);
//客户端管理器
typedef struct _ops_bridge_manager {
    struct _ops_global* global;             //全局
    uv_loop_t* loop;                        //事件循环
    struct _ops_key_tree key;               //授权数据
    struct _ops_bridge_tree bridge;         //客户端
    uint32_t bridge_count;                  //客户端数量
    uint32_t bridge_online;                 //在线客户端数量
    uv_tcp_t listen;                        //监听
    struct messagepool m_mp;                //接收缓冲
    uv_timer_t ping_timer;                  //ping定时器
    ops_module* modules[256];               //模块
}ops_bridge_manager;

static int _ops_bridge_compare(ops_bridge* w1, ops_bridge* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_bridge_tree, _ops_bridge, entry, _ops_bridge_compare)
static int _ops_key_compare(ops_key* w1, ops_key* w2) {
    return strcmp(w1->key, w2->key);
}
RB_GENERATE_STATIC(_ops_key_tree, _ops_key, entry, _ops_key_compare)

//发送回调
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}

//查找客户端
ops_bridge* bridge_find(ops_bridge_manager* manager, uint16_t id) {
    ops_bridge ths = {
        .id = id
    };
    return RB_FIND(_ops_bridge_tree, &manager->bridge, &ths);
}
//获取客户端ID
uint16_t bridge_id(ops_bridge* bridge) {
    return bridge->id;
}
//获取全局对象
ops_global* bridge_manager_global(ops_bridge_manager* manager) {
    return manager->global;
}
//向客户发送数据
void bridge_send_raw(ops_bridge* bridge, uv_buf_t* buf) {
#if HAVE_QUIC
    if (bridge->type == 2) {
        if (!bridge->stream) {
            free(buf->base);
            return;
        }
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
    req->data = buf->base;
    uv_write(req, &bridge->tcp, buf, 1, write_cb);
}
//向客户发送数据
void bridge_send_auth(ops_bridge* bridge, const char* data, uint32_t len) {
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
    bridge_send_raw(bridge, &buf);
}
//向客户发送数据
void bridge_send_mod(ops_bridge* bridge, uint8_t mod, uint8_t type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len) {
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
    bridge_send_raw(bridge, &buf);
}
//向客户发送数据
static void bridge_send_ping(ops_bridge* bridge, const char* data, uint32_t len) {
    uv_buf_t buf[] = { 0 };
    buf->len = 4 + sizeof(ops_packet) + len;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    *(uint32_t*)(buf->base) = htonl(buf->len - 4);
    ops_packet* pack = (ops_packet*)(buf->base + 4);
    pack->type = ops_packet_ping;
    if (data && len) {
        memcpy(pack->mod.data, data, len);
    }
    bridge_send_raw(bridge, &buf);
}
//客户端鉴权成功
static void bridge_auth_ok(ops_bridge* bridge) {
    //加载模块数据
    for (size_t i = 0; i < 3; i++) {
        bridge->manager->modules[i]->on_load(bridge->manager->modules[i], bridge);
    }
    //更新统计
    bridge->manager->bridge_online++;
}
//收到客户端数据
static void bridge_on_data(ops_bridge* bridge, char* data, int size) {
    if (size < sizeof(ops_packet))
        return;
    ops_packet* packet = (ops_packet*)data;
    size -= sizeof(ops_packet);
    switch (packet->type)
    {
    case ops_packet_auth: {
        //读取key长度
        uint16_t key_len = ntohs(*(uint16_t*)(&packet->data));
        packet->data[key_len + 2] = 0;
        ops_key _key = {
            .key = packet->data + 2
        };
        ops_key* key = RB_FIND(_ops_key_tree, &bridge->manager->key, &_key);
        if (key == NULL) {
            char buf[1];
            buf[0] = CTL_AUTH_ERR;//鉴权成功
            bridge_send_auth(bridge, buf, sizeof(buf));
        }
        else {
            //查找ID是否存在
            ops_bridge* p = bridge_find(bridge->manager, key->id);
            if (p != NULL) {
                //鉴权成功,但已经在线
                char buf[1];
                buf[0] = CTL_AUTH_ONLINE;//鉴权成功
                bridge_send_auth(bridge, buf, sizeof(buf));
            }
            else {
                char buf[1];
                buf[0] = CTL_AUTH_OK;//鉴权成功
                bridge_send_auth(bridge, buf, sizeof(buf));
                //记录客户端
                bridge->id = key->id;
                RB_INSERT(_ops_bridge_tree, &bridge->manager->bridge, bridge);
                //记录ping
                bridge->last_ping = uv_now(bridge->manager->loop);
                bridge_auth_ok(bridge);
            }
        }
        break;
    }
    case ops_packet_ping: {
        uint64_t t = *(uint64_t*)&packet->data[0];
        bridge->ping = ntohl(*(uint32_t*)&packet->data[8]);
        bridge_send_ping(bridge, packet->data, 8);
        bridge->last_ping = uv_now(bridge->manager->loop);
        break;
    }
    case ops_packet_mod: {
        packet->mod.service_id = ntohl(packet->mod.service_id);
        packet->mod.stream_id = ntohl(packet->mod.stream_id);
        //查找模块
        ops_module* mod = bridge->manager->modules[packet->mod.mod];
        if (mod == NULL) {
            break;
        }
        mod->on_data(mod, bridge, packet->mod.type, packet->mod.stream_id, packet->mod.service_id, packet->mod.data, size);
        break;
    }
    default:
        break;
    }
}
//关闭
static void bridge_on_close(ops_bridge* bridge) {
    //通知对端服务
    /*
    ops_forwards* fc = NULL;
    RB_FOREACH(fc, _ops_forwards_tree, &bridge->global->forwards) {
        //来源
        if (fc->src_id == bridge->id) {

        }
        //出口
        if (fc->dst_id == bridge->id) {

        }
    }
    */
    //从句柄树中移除
    RB_REMOVE(_ops_bridge_tree, &bridge->manager->bridge, bridge);
    //
    //heap_remove(&bridge->global->ping_heap, &bridge->heap, ping_less_than);
    bridge->manager->bridge_online--;
    //回收资源
    databuffer_clear(&bridge->m_buffer, &bridge->manager->m_mp);
    free(bridge);
}
static void bridge_close_cb(uv_handle_t* handle) {
    ops_bridge* bridge = (ops_bridge*)handle->data;
    bridge_on_close(bridge);
}
static void bridge_shutdown_cb(uv_shutdown_t* req, int status) {
    ops_bridge* bridge = (ops_bridge*)req->data;
    uv_close(&bridge->tcp, bridge_close_cb);
    free(req);
}
//读取到数据
static void bridge_on_read(ops_bridge* bridge, uint8_t* buf, size_t len) {
    ops_bridge_manager* manager = bridge->manager;
    //记录到缓冲区
    databuffer_push(&bridge->m_buffer, &manager->m_mp, buf, len);
    for (;;) {
        int size = databuffer_readheader(&bridge->m_buffer, &manager->m_mp, 4);
        if (size < 0) {
            return;
        }
        char* temp = malloc(size);
        databuffer_read(&bridge->m_buffer, &manager->m_mp, temp, size);
        bridge_on_data(bridge, temp, size);
        databuffer_reset(&bridge->m_buffer);
    }
}
static void bridge_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_bridge* bridge = (ops_bridge*)tcp->data;
    if (nread <= 0) {
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
//连接进入
static void bridge_connection_cb(uv_stream_t* tcp, int status) {
    ops_bridge_manager* manager = (ops_global*)tcp->data;
    ops_bridge* bridge = (ops_bridge*)malloc(sizeof(ops_bridge));//为tcp bridge申请资源
    if (!bridge)
        return;
    memset(bridge, 0, sizeof(*bridge));
    bridge->manager = manager;

    uv_tcp_init(ops_get_loop(manager->global), &bridge->tcp);//初始化tcp bridge句柄
    bridge->tcp.data = bridge;
    //bridge->type = 1;

    if (uv_accept(tcp, (uv_stream_t*)&bridge->tcp) == 0) {
        //新客户
        printf("New Client\r\n");
        //提取ip
        int namelen = sizeof(bridge->peer);
        uv_tcp_getpeername(&bridge->tcp, &bridge->peer, &namelen);
        namelen = sizeof(bridge->peer);
        uv_tcp_getsockname(&bridge->tcp, &bridge->local, &namelen);
        uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);
    }
}
//ping检查定时器
static void bridge_ping_timer_cb(uv_timer_t* handle) {
    ops_bridge_manager* manager = (ops_bridge_manager*)handle->data;
    ops_bridge* bridge;
    RB_FOREACH(bridge, _ops_bridge_tree, &manager->bridge) {
        if (bridge->last_ping > (uv_now(manager->loop) - 1000 * 30))
            continue;
        //踢掉用户
        //if (bridge->type == 2) {
        //    if (bridge->conn) {
        //        lsquic_conn_close(bridge->conn);
        //    }
        //}
        //else {
        if (bridge->b.quit == 0) {
            bridge->b.quit = 1;
            uv_close(&bridge->tcp, bridge_close_cb);
        }
        //}
    }
}

//创建网桥管理器
ops_bridge_manager* bridge_manager_new(ops_global* global) {
    ops_bridge_manager* manager = malloc(sizeof(*manager));
    if (!manager)
        return NULL;
    memset(manager, 0, sizeof(*manager));
    manager->global = global;
    manager->loop = ops_get_loop(global);
    RB_INIT(&manager->bridge);
    //创建模块
    manager->modules[MODULE_FORWARD] = forward_module_new(manager);
    manager->modules[MODULE_DST] = dst_module_new(manager);
    manager->modules[MODULE_VPC] = vpc_module_new(manager);
    //开始监听
    manager->listen.data = manager;
    uv_tcp_init(ops_get_loop(global), &manager->listen);
    struct sockaddr_in6 addr;
    uv_ip6_addr("::0", opc_get_config(global)->bridge_port, &addr);
    uv_tcp_bind(&manager->listen, &addr, 0);
    uv_listen((uv_stream_t*)&manager->listen, 128, bridge_connection_cb);
    //
    uv_timer_init(ops_get_loop(global), &manager->ping_timer);
    manager->ping_timer.data = manager;
    uv_timer_start(&manager->ping_timer, bridge_ping_timer_cb, 1000 * 5, 1000 * 5);
    printf("Bridge Start\r\n");
    return manager;
}
//释放网桥管理器
void bridge_manager_delete(ops_bridge_manager* manager) {

    free(manager);
}
//管理器控制
void bridge_mgr_ctrl(ops_bridge_manager* manager, ops_mgr_ctrl* ctrl) {
    switch (ctrl->type)
    {
    case ops_mgr_ctrl_key_add: {
        ops_key* key = malloc(sizeof(*key));
        if (key == NULL)
            return;
        memset(key, 0, sizeof(*key));
        key->id = ctrl->add.id;
        key->key = strdup(ctrl->add.k);
        RB_INSERT(_ops_key_tree, &manager->key, key);
        manager->bridge_count++;
        break;
    }
    case ops_mgr_ctrl_key_del: {
        ops_key _key = {
            .key = ctrl->del.k
        };
        ops_key* key = RB_FIND(_ops_key_tree, &manager->key, &_key);
        if (key == NULL) {
            return;
        }
        free(key->key);
        //踢出相关客户端

        RB_REMOVE(_ops_key_tree, &manager->key, key);
        free(key);
        manager->bridge_count--;
        break;
    }
    case ops_mgr_ctrl_key_new: {
        ops_key _key = {
            .key = ctrl->new.k
        };
        ops_key* key = RB_FIND(_ops_key_tree, &manager->key, &_key);
        if (key == NULL) {
            return;
        }
        free(key->key);
        key->key = strdup(ctrl->new.k);
        //重置后踢出相关客户端

        break;
    }
    default:
        break;
    }
}
//模块控制
void* bridge_mod_ctrl(ops_bridge_manager* manager, uint8_t mod, void* ctrl) {
    return manager->modules[mod]->on_ctrl(manager->modules[mod], ctrl);
}
