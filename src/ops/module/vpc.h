#ifndef __vpc_h__
#define __vpc_h__
#include <module/vpc.h>
#include "../bridge.h"


enum ops_vpc_ctrl_type {
    ops_vpc_ctrl_vpc_add = 1,
    ops_vpc_ctrl_vpc_del,
    ops_vpc_ctrl_member_add,
    ops_vpc_ctrl_member_del,
};

typedef struct _ops_vpc_ctrl {
    enum ops_vpc_ctrl_type type;
    union {
        struct {
            uint16_t id;
            const char* ipv4;
            const char* ipv6;
        }vpc_add;
        struct {
            uint16_t id;
        }vpc_del;
        struct {
            uint32_t id;
            uint16_t bid;
            uint16_t vid;
            const char* ipv4;
            const char* ipv6;
        }member_add;
        struct {
            uint32_t id;
        }member_del;
    };
} ops_vpc_ctrl;

typedef struct _ops_module_vpc ops_module_vpc;

//创建目标模块
ops_module_vpc* vpc_module_new(ops_bridge_manager* manager);

#endif // !__dst_h__
