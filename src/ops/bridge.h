#ifndef __bridge_h__
#define __bridge_h__
#include <stdint.h>
#include "ops.h"

enum ops_mgr_ctrl_type {
    ops_mgr_ctrl_key_add = 1,
    ops_mgr_ctrl_key_del,
    ops_mgr_ctrl_key_new,
};

typedef struct _ops_mgr_ctrl {
    enum ops_mgr_ctrl_type type;
    union {
        struct {
            uint16_t id;
            const char* k;
        }add;
        struct {
            const char* k;
        }del;
        struct {
            uint16_t id;
            const char* k;
        }new;
    };
} ops_mgr_ctrl;

//客户端
typedef struct _ops_bridge ops_bridge;
//客户端管理器
typedef struct _ops_bridge_manager ops_bridge_manager;

//模块
typedef void (*ops_module_on_load) (struct _ops_module* mod, ops_bridge* bridge);
typedef void (*ops_module_on_data) (struct _ops_module* mod, ops_bridge* bridge, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size);
typedef void* (*ops_module_on_ctrl) (struct _ops_module* mod, void* ctrl);
typedef struct _ops_module {
    ops_module_on_load on_load;
    ops_module_on_data on_data;
    ops_module_on_ctrl on_ctrl;
} ops_module;


//创建网桥管理器
ops_bridge_manager* bridge_manager_new(ops_global* global);
//获取全局对象
ops_global* bridge_manager_global(ops_bridge_manager* manager);
//获取客户数量
uint32_t bridge_manager_count(ops_bridge_manager* manager);
//获取在线数量
uint32_t bridge_manager_online(ops_bridge_manager* manager);

//查找客户端
ops_bridge* bridge_find(ops_bridge_manager* manager, uint16_t id);
//获取客户端ID
uint16_t bridge_id(ops_bridge* bridge);
//获取客户端地址
struct sockaddr_storage* bridge_peer(ops_bridge* bridge);
//获取本地地址
struct sockaddr_storage* bridge_local(ops_bridge* bridge);
//获取延迟
uint32_t bridge_ping(ops_bridge* bridge);
//向客户发送数据
void bridge_send_mod(ops_bridge* bridge, uint8_t mod, uint8_t type, uint32_t service_id, uint32_t stream_id, const char* data, uint32_t len);
//管理器控制
void bridge_mgr_ctrl(ops_bridge_manager* manager, ops_mgr_ctrl* ctrl);
//模块控制
void* bridge_mod_ctrl(ops_bridge_manager* manager, uint8_t mod, void* ctrl);

#endif  // !__bridge_h__
