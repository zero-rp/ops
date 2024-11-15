#ifndef __bridge_h_
#define __bridge_h_

#include "opc.h"
//网桥
typedef struct _opc_bridge  opc_bridge;

//模块
typedef void (*opc_module_on_data) (struct _opc_module* mod, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size);
typedef struct _opc_module {
    opc_module_on_data on_data;
} opc_module;

//从网桥发送数据
void bridge_send_raw(opc_bridge* bridge, uv_buf_t* buf);
//向服务器发送数据
void bridge_send_mod(opc_bridge* bridge, uint8_t mod, uint8_t  type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
void bridge_send_auth(opc_bridge* bridge, const char* data, uint32_t len);
//连接服务器
int bridge_connect(opc_bridge* bridge);
//创建对象
opc_bridge* bridge_new(opc_global* global);
//释放对象
void bridge_delete(opc_bridge* bridge);
//引用
opc_bridge* bridge_ref(opc_bridge* bridge);
//解引用
void bridge_unref(opc_bridge * bridge);
//
uv_loop_t* bridge_loop(opc_bridge* bridge);

#endif // !__bridge_h_

