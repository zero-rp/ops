#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <uv/tree.h>
#include "public.h"
#include "module/dst.h"
typedef struct _ops_pub_conn {
    RB_ENTRY(_ops_pub_conn) entry;          //
    struct _ops_pub* pub;
    uint32_t id;
    uv_tcp_t tcp;
}ops_pub_conn;
RB_HEAD(_ops_pub_conn_tree, _ops_pub_conn);
typedef struct _ops_pub {
    RB_ENTRY(_ops_pub) entry;          //
    struct _ops_public* public;         //公共服务
    uint32_t id;                        //服务ID
    uint16_t dst_id;                    //目标客户ID
    uint32_t dst;                       //目标ID
    union {
        uv_tcp_t tcp;
        uv_tcp_t udp;
    };
}ops_pub;
RB_HEAD(_ops_pub_tree, _ops_pub);
typedef struct _ops_public {
    ops_global* global;
    ops_bridge_manager* manager;            //客户端管理器
    struct _ops_pub_tree pub;
    uint32_t conn_id;                       //连接ID
    struct _ops_pub_conn_tree conn;         //连接
}ops_public;

static int _ops_pub_compare(ops_pub* w1, ops_pub* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_pub_tree, _ops_pub, entry, _ops_pub_compare)
static int _ops_pub_conn_compare(ops_pub_conn* w1, ops_pub_conn* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_pub_conn_tree, _ops_pub_conn, entry, _ops_pub_conn_compare)

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
//发送回调
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
//连接关闭
static void public_close_cb(uv_handle_t* handle) {
    ops_pub_conn* conn = (ops_pub_conn*)handle->data;
    if (conn->id) {
        RB_REMOVE(_ops_pub_conn_tree, &conn->pub->public->conn, conn);
    }
    free(conn);
}
static void public_shutdown_cb(uv_shutdown_t* req, int status) {
    ops_pub_conn* conn = (ops_pub_conn*)req->data;
    uv_close(&conn->tcp, public_close_cb);
    free(req);
}
static void public_shutdown(ops_pub_conn* conn) {
    //shutdown
    uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(*req));
    if (req != NULL) {
        memset(req, 0, sizeof(*req));
        req->data = conn;
        uv_shutdown(req, &conn->tcp, public_shutdown_cb);
    }
    else {
        //分配内存失败,直接强制关闭
        uv_close(&conn->tcp, public_close_cb);
    }
}
//tcp连接进入
static void _connection_cb(uv_stream_t* tcp, int status) {
    ops_pub* pub = tcp->data;
    if (status < 0) {
        return;
    }
    ops_pub_conn* conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
    uv_tcp_init(ops_get_loop(pub->public->global), &conn->tcp);
    conn->tcp.data = conn;
    conn->pub = pub;
    if (uv_accept(tcp, (uv_stream_t*)&conn->tcp) == 0) {
        //查找目标是否在线
        ops_bridge* b = bridge_find(pub->public->manager, pub->dst_id);
        if (b == NULL) {
            //关闭连接
            public_shutdown(conn);
            return;
        }
        //
        conn->id = pub->public->conn_id++;
        RB_INSERT(_ops_pub_conn_tree, &pub->public->conn, conn);
        //打开目标
        uint8_t buf[1];
        buf[0] = CTL_DST_CTL_OPEN;
        bridge_send_mod(b, MODULE_DST, dst_packet_ctl, pub->dst, conn->id, buf, sizeof(buf));
    }
    else {
        free(conn);
    }
}
//读取到数据
static void _read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ops_pub_conn* conn = (ops_pub_conn*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开
            uv_close(tcp, public_close_cb);
        }
        else {
            //shutdown
            public_shutdown(conn);
        }
        return;
    }
    //查找客户端
    ops_bridge* b = bridge_find(conn->pub->public->manager, conn->pub->dst_id);
    if (b == NULL) {
        //关闭连接
        public_shutdown(conn);
        return;
    }
    bridge_send_mod(b, MODULE_DST, dst_packet_data, conn->pub->dst, conn->id, buf->base, nread);
    free(buf->base);
}
ops_public* public_new(ops_global* global, ops_bridge_manager* manager) {
    ops_public* public = (ops_public*)malloc(sizeof(*public));
    if (public == NULL) {
        return NULL;
    }
    memset(public, 0, sizeof(*public));
    public->global = global;
    public->manager = manager;
    public->conn_id = 1;
    RB_INIT(&public->pub);
    RB_INIT(&public->conn);
    return public;
}
//控制数据
void public_ctl(ops_public* pub, ops_bridge* bridge, uint32_t stream_id, uint8_t* data, int size) {
    ops_pub_conn the = {
        .id = stream_id
    };
    ops_pub_conn* conn = RB_FIND(_ops_pub_conn_tree, &pub->conn, &the);
    if (conn == NULL) {
        return;
    }
    //读取类型
    uint8_t type = data[0];
    switch (type)
    {
    case CTL_DST_CTL_SUC: {//连接远端成功
        //开始接收数据
        uv_read_start((uv_stream_t*)&conn->tcp, alloc_buffer, _read_cb);
        break;
    }
    case CTL_DST_CTL_ERR: {//连接远端失败
        public_shutdown(conn);
        break;
    }
    default:
        break;
    }
}
//转发客户端数据到远端
void public_data(ops_public* pub, uint32_t stream_id, uint8_t* data, int size) {
    ops_pub_conn the = {
        .id = stream_id
    };
    ops_pub_conn* conn = RB_FIND(_ops_pub_conn_tree, &pub->conn, &the);
    if (conn == NULL) {
        //目标已经不在了,关闭连接
        return;
    }
    //发送数据
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
    uv_write(req, &conn->tcp, &buf, 1, write_cb);
}
void public_add(ops_public* public, uint32_t id, uint16_t port, uint16_t dst_id, uint8_t type, const char* bind, const char* dst, uint16_t dst_port) {
    ops_pub* pub = malloc(sizeof(*pub));
    if (pub == NULL)
        return;
    memset(pub, 0, sizeof(*pub));
    pub->public = public;
    //监听
    if (type == dst_type_tcp) {
        uv_tcp_init(ops_get_loop(public->global), &pub->tcp);
        pub->tcp.data = pub;
        struct sockaddr_in6 addr;
        uv_ip6_addr("::0", port, &addr);
        uv_tcp_bind(&pub->tcp, (const struct sockaddr*)&addr, 0);
        uv_listen((uv_stream_t*)&pub->tcp, 128, _connection_cb);
    }
    else if (type == dst_type_udp) {
        uv_udp_init(ops_get_loop(public->global), &pub->udp);
        pub->udp.data = pub;
        struct sockaddr_in6 addr;
        uv_ip6_addr("::0", port, &addr);
        uv_udp_bind(&pub->udp, (const struct sockaddr*)&addr, 0);
        uv_udp_recv_start(&pub->udp, NULL, NULL);
    }
    else {
        free(pub);
        return;
    }
    //添加目标服务
    ops_dst_ctrl ctrl;
    ctrl.type = ops_dst_ctrl_add;
    ctrl.add.src_type = ops_src_type_public;
    ctrl.add.dst_id = dst_id;
    ctrl.add.type = type;
    ctrl.add.bind = bind;
    ctrl.add.dst = dst;
    ctrl.add.dst_port = dst_port;
    int dsts_id = bridge_mod_ctrl(public->manager, MODULE_DST, &ctrl);
    if (!dsts_id) {
        free(pub);
        return;
    }
    pub->id = id;
    pub->dst_id = dst_id;
    //目标
    pub->dst = dsts_id;
    RB_INSERT(_ops_pub_tree, &public->pub, pub);
    //下发到相关通道
    ops_bridge* b = bridge_find(public->manager, dst_id);
    if (b) {
        //pub_push_dst(b, pub);
    }
}