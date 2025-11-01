#include <stdlib.h>
#include <string.h>
#include <uv/tree.h>

#include <common/sds.h>
#include "dst.h"
#include "forward.h"
#include "../http.h"
#include "../ops.h"
#include "../public.h"

//目标服务
typedef struct _ops_dsts {
    RB_ENTRY(_ops_dsts) entry;          //
    uint32_t id;                        //目标ID
    uint16_t dst_id;                    //目标客户ID
    uint16_t src_id;                    //来源客户ID
    enum ops_src_type src_type;         //源服务类型
    ops_dst dst;                        //目标信息
}ops_dsts;
RB_HEAD(_ops_dsts_tree, _ops_dsts);

//转发模块
typedef struct _ops_module_dst {
    ops_module mod;                         //模块
    ops_bridge_manager* manager;            //管理器
    struct _ops_dsts_tree dst;              //目标
    uint32_t dst_id;
}ops_module_dst;


static int _ops_dsts_compare(ops_dsts* w1, ops_dsts* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_dsts_tree, _ops_dsts, entry, _ops_dsts_compare)

//数据处理
static void _ctl(ops_module_dst* module, ops_bridge* bridge, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    //查找服务
    ops_dsts ths = {
        .id = service_id
    };
    ops_dsts* p = RB_FIND(_ops_dsts_tree, &module->dst, &ths);
    if (p == NULL) {
        uint8_t buf[1];
        buf[0] = CTL_DST_CTL_ERR;//错误,服务已经不在了
        bridge_send_mod(bridge, MODULE_DST, dst_packet_ctl, service_id, stream_id, buf, sizeof(buf));
        return;
    }
    switch (p->src_type)
    {
    case ops_src_type_host: {
        http_host_ctl(ops_get_http(bridge_manager_global(module->manager)), bridge, stream_id, data, size);
        break;
    }
    case ops_src_type_public: {
        public_ctl(ops_get_public(bridge_manager_global(module->manager)), bridge, stream_id, data, size);
        break;
    }
    case ops_src_type_forward: {
        //查找来源客户端是否存在
        ops_bridge* b = bridge_find(module->manager, p->src_id);
        if (b == NULL) {
            //来源已经不存在
            uint8_t buf[1];
            buf[0] = CTL_DST_CTL_ERR;//错误
            bridge_send_mod(bridge, MODULE_DST, dst_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            break;
        }
        switch (data[0])
        {
        case CTL_DST_CTL_SUC: {//打开成功
            //发送
            uint8_t buf[5];
            buf[0] = CTL_FORWARD_CTL_SUC;
            memcpy(&buf[1], &data[1], 4);//对端ID
            bridge_send_mod(b, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            break;
        }
        case CTL_DST_CTL_ERR: {//异常
            //发送
            uint8_t buf[1];
            buf[0] = CTL_FORWARD_CTL_ERR;
            bridge_send_mod(b, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            break;
        }
        default:
            break;
        }
        break;
    }
    default:
        break;
    }
}
static void _data(ops_module_dst* module, ops_bridge* bridge, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    //查找服务
    ops_dsts ths = {
        .id = service_id
    };
    ops_dsts* p = RB_FIND(_ops_dsts_tree, &module->dst, &ths);
    if (p == NULL) {
        uint8_t buf[1];
        buf[0] = CTL_DST_CTL_ERR;//错误,服务已经不在了
        bridge_send_mod(bridge, MODULE_DST, dst_packet_ctl, service_id, stream_id, buf, sizeof(buf));
        return;
    }
    switch (p->src_type)
    {
    case ops_src_type_host: {
        http_host_data(ops_get_http(bridge_manager_global(module->manager)), stream_id, data, size);
        break;
    }
    case ops_src_type_public: {
        public_data(ops_get_public(bridge_manager_global(module->manager)), stream_id, data, size);
        break;
    }
    case ops_src_type_forward: {
        //查找来源客户端是否存在
        ops_bridge* b = bridge_find(module->manager, p->src_id);
        if (b == NULL) {
            //来源已经不存在
            uint8_t buf[1];
            buf[0] = CTL_DST_CTL_ERR;//错误
            bridge_send_mod(bridge, MODULE_DST, dst_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            break;
        }
        //发送
        bridge_send_mod(b, MODULE_FORWARD, forward_packet_data, 0, stream_id, data, size);
        break;
    }
    default:
        break;
    }
}
static void dst_data(ops_module_dst* module, ops_bridge* bridge, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case dst_packet_ctl:
        _ctl(module, bridge, stream_id, service_id, data, size);
        break;
    case dst_packet_data:
        _data(module, bridge, stream_id, service_id, data, size);
        break;
    default:
        break;
    }
}
//加载服务
static void dst_load(ops_module_dst* module, ops_bridge* bridge) {
    sds pack = sdsnewlen(NULL, 5);//预留数量和指令
    pack[0] = CTL_DST_ADD;
    int count = 0;
    //查询客户端转发服务
    ops_dsts* tc = NULL;
    RB_FOREACH(tc, _ops_dsts_tree, &module->dst) {
        if (tc->dst_id == bridge_id(bridge)) {
            ops_dst dst;
            dst.port = htons(tc->dst.port);
            dst.sid = htonl(tc->dst.sid);
            dst.type = tc->dst.type;
            memcpy(dst.dst, tc->dst.dst, sizeof(dst.dst));
            memcpy(dst.bind, tc->dst.bind, sizeof(dst.bind));
            pack = sdscatlen(pack, &dst, sizeof(ops_dst));
            count++;
        }
    }
    *(uint32_t*)(&pack[1]) = htonl(count);
    //下发转发服务
    if (count > 0) {
        bridge_send_mod(bridge, MODULE_DST, dst_packet_dst, 0, 0, pack, sdslen(pack));
    }
    sdsfree(pack);
}
//控制
static void* dst_ctrl(ops_module_dst* module, ops_dst_ctrl* ctrl) {
    switch (ctrl->type)
    {
    case ops_dst_ctrl_add: {
        ops_dsts* dst = malloc(sizeof(*dst));
        if (!dst)
            return NULL;
        memset(dst, 0, sizeof(*dst));
        module->dst_id++;
        dst->id = module->dst_id;
        dst->dst_id = ctrl->add.dst_id;
        dst->src_type = ctrl->add.src_type;
        dst->src_id = ctrl->add.src_id;
        dst->dst.sid = dst->id;
        dst->dst.type = ctrl->add.type;
        dst->dst.port = ctrl->add.dst_port;
        strncpy(dst->dst.dst, ctrl->add.dst, sizeof(dst->dst.dst) - 1);
        dst->dst.dst[sizeof(dst->dst.dst) - 1] = 0;
        strncpy(dst->dst.bind, ctrl->add.bind, sizeof(dst->dst.bind) - 1);
        dst->dst.bind[sizeof(dst->dst.bind) - 1] = 0;
        RB_INSERT(_ops_dsts_tree, &module->dst, dst);
        return (void *)dst->id;
    }
    default:
        break;
    }
}
//创建目标模块
ops_module_dst* dst_module_new(ops_bridge_manager* manager) {
    ops_module_dst* mod = malloc(sizeof(*mod));
    if (!mod)
        return NULL;
    memset(mod, 0, sizeof(*mod));
    mod->manager = manager;
    mod->mod.on_load = (ops_module_on_load)dst_load;
    mod->mod.on_data = (ops_module_on_data)dst_data;
    mod->mod.on_ctrl = (ops_module_on_ctrl)dst_ctrl;
    return mod;
}