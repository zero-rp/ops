#ifndef __forward_h__
#define __forward_h__

#include <module/forward.h>
#include "../bridge.h"
enum ops_forward_ctrl_type {
    ops_forward_ctrl_add = 1,
    ops_forward_ctrl_update,
    ops_forward_ctrl_del,
};

typedef struct _ops_forward_ctrl {
    enum ops_forward_ctrl_type type;
    union {
        struct {
            uint32_t id;
            uint16_t src_id;
            uint16_t dst_id;
            uint8_t type;
            uint16_t src_port;
            const char* bind;
            const char* dst;
            uint16_t dst_port;
        }add;
        struct {
            uint32_t id;
            uint16_t src_id;
            uint16_t dst_id;
            uint8_t type;
            uint16_t src_port;
            const char* bind;
            const char* dst;
            uint16_t dst_port;
        }update;
        struct {
            uint32_t id;
        }del;
    };
} ops_forward_ctrl;

typedef struct _ops_module_forward ops_module_forward;

//创建转发模块
ops_module_forward* forward_module_new(ops_bridge_manager* manager);

#endif // !__forward_h__
