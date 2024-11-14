#ifndef __vpc_h__
#define __vpc_h__
#include <module/vpc.h>
#include "../bridge.h"

typedef struct _module_vpc module_vpc;

//创建模块
module_vpc* vpc_module_new(opc_bridge* bridge);
//释放模块
void vpc_module_delete(module_vpc* mod);

#endif // !__vpc_h__
