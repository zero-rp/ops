#include <uv.h>
#include <cJSON.h>
#include <databuffer.h>

#define DEFAULT_BACKLOG 128


typedef struct write_req_t {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;
typedef struct _ops_global {
    uv_tcp_t tcp;                       //连接
    struct messagepool m_mp;            //接收缓冲
    uv_timer_t re_time;                 //重连定时器

}ops_global;
//
typedef struct _ops_bridge {
    uv_tcp_t tcp;       //
    ops_global* global;
    struct databuffer m_buffer;         //接收缓冲

}ops_bridge;
//


static uv_loop_t* loop = NULL;

//分配内存
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}

//
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



        databuffer_reset(&bridge->m_buffer);
    }
}

//连接返回
static void bridge_connect(uv_connect_t* req, int status) {
    ops_bridge* bridge = (ops_bridge*)req->data;
    if (status < 0) {
        //连接失败
        printf("out_remote_connect_error\r\n");
        //定时重连
        uv_timer_start();
        return;
    }
    //连接成功,
    uv_read_start((uv_stream_t*)&bridge->tcp, alloc_buffer, bridge_read_cb);
}
//启动连接
static int start_connect(ops_global *global) {
    ops_bridge* bridge = (ops_bridge*)malloc(sizeof(*bridge));
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
    req->data = bridge;
    struct sockaddr_in _addr;
    uv_ip4_addr("127.0.0.1", 1664, &_addr);
    uv_tcp_connect(req, &bridge->tcp,&_addr, bridge_connect);

}
//
static int init_global(ops_global* global) {
    uv_timer_init(loop, &global->re_time);


}


int main() {
    loop = uv_default_loop();
    ops_global* global = (ops_global*)malloc(sizeof(ops_global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //
    start_connect(global);

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
