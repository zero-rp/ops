#ifndef __forward_h_
#define __forward_h_

#include <module/forward.h>
#include "../bridge.h"


typedef struct _module_forward module_forward;

//创建转发模块
module_forward* forward_module_new(opc_bridge* bridge);
//释放转发模块
void forward_module_delete(module_forward* mod);



//回收资源
void forward_free(opc_bridge* bridge);

//-----------------------------------------------------服务器控制回调
void forward(opc_bridge* bridge, ops_packet* packet);
void forward_ctl(opc_bridge* bridge, ops_packet* packet);
void forward_data(opc_bridge* bridge, ops_packet* packet, int size);

#endif // !__forward_h_
