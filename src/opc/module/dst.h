#ifndef __dst_h__
#define __dst_h__
#include <module/dst.h>
#include "../bridge.h"

typedef struct _module_dst module_dst;

//创建转发模块
module_dst* dst_module_new(opc_bridge* bridge);
//释放转发模块
void dst_module_delete(module_dst* mod);

#endif // !__dst_h__
