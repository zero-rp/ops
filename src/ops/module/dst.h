#ifndef __dst_h__
#define __dst_h__
#include <module/dst.h>
#include "../bridge.h"

//源类型
enum ops_src_type {
    ops_src_type_host = 1,
    ops_src_type_forward,
};

enum ops_dst_ctrl_type {
    ops_dst_ctrl_add = 1,
};

typedef struct _ops_dst_ctrl {
    enum ops_dst_ctrl_type type;
    union {
        struct {
            enum ops_src_type src_type;
            uint16_t dst_id;
            uint16_t src_id;
            uint8_t type;
            const char* bind;
            const char* dst;
            uint16_t dst_port;
        }add;
    };
} ops_dst_ctrl;

typedef struct _ops_module_dst ops_module_dst;

//创建目标模块
ops_module_dst* dst_module_new(ops_bridge_manager* manager);

#endif // !__dst_h__
