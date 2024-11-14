#include <uv/tree.h>

#include <common/common.h>
#include <common/sds.h>
#include <module/forward.h>

#include "dst.h"
#include "forward.h"
#include "../bridge.h"

//转发服务
typedef struct _ops_forwards {
    RB_ENTRY(_ops_forwards) entry;       //
    uint32_t id;                        //转发服务ID
    uint16_t src_id;                    //来源客户ID
    uint16_t dst_id;                    //目标客户ID
    uint32_t dst;                       //目标服务ID
    ops_forward src;                    //来源信息
}ops_forwards;
RB_HEAD(_ops_forwards_tree, _ops_forwards);
//转发模块
typedef struct _ops_module_forward {
    ops_module mod;                         //模块
    ops_bridge_manager* manager;            //客户端管理器
    struct _ops_forwards_tree forwards;     //转发器
}ops_module_forward;

static int _ops_forwards_compare(ops_forwards* w1, ops_forwards* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_forwards_tree, _ops_forwards, entry, _ops_forwards_compare)


static void forward_push_src(ops_bridge* bridge, ops_forwards* p) {
    char buf[1 + 4 + sizeof(ops_forward)];
    buf[0] = CTL_FORWARD_ADD;
    *(uint32_t*)(&buf[1]) = htonl(1);
    ops_forward _src;
    _src.port = htons(p->src.port);
    _src.sid = htonl(p->src.sid);
    _src.type = p->src.type;
    memcpy(&buf[5], &_src, sizeof(_src));
    bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_forward, 0, 0, buf, sizeof(buf));
}
static void forward_push_del(ops_bridge* bridge, uint32_t sid) {
    char buf[1 + 4];
    buf[0] = CTL_FORWARD_DEL;
    *(uint32_t*)(&buf[1]) = htonl(sid);
    bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_forward, 0, 0, buf, sizeof(buf));
}



//加载服务
static void forward_load(ops_module_forward* module, ops_bridge* bridge) {
    sds pack = sdsnewlen(NULL, 5);//预留数量和指令
    pack[0] = CTL_FORWARD_ADD;
    int count = 0;
    //查询客户端转发服务
    ops_forwards* tc = NULL;
    RB_FOREACH(tc, _ops_forwards_tree, &module->forwards) {
        //来源
        if (tc->src_id == bridge_id(bridge)) {
            ops_forward src;
            src.port = htons(tc->src.port);
            src.sid = htonl(tc->src.sid);
            src.type = tc->src.type;
            pack = sdscatlen(pack, &src, sizeof(ops_forward));
            count++;
        }
    }
    *(uint32_t*)(&pack[1]) = htonl(count);
    //下发转发服务
    if (count > 0) {
        bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_forward, 0, 0, pack, sdslen(pack));
    }
    sdsfree(pack);
}
//数据处理
static void forward_data(ops_module_forward* module, ops_bridge* bridge, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case forward_packet_ctl: {
        //查找服务
        ops_forwards ths = {
            .id = service_id
        };
        ops_forwards* p = RB_FIND(_ops_forwards_tree, &module->forwards, &ths);
        if (p == NULL) {
            uint8_t buf[1];
            buf[0] = CTL_FORWARD_CTL_ERR;//错误
            bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            return;
        }
        uint8_t type = data[0];
        switch (type)
        {
        case CTL_FORWARD_CTL_OPEN: {//发起请求
            //查找目标客户端是否存在
            ops_bridge* b = bridge_find(module->manager, p->dst_id);
            if (b == NULL) {
                uint8_t buf[1];
                buf[0] = CTL_FORWARD_CTL_ERR;//错误
                bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
                break;
            }
            //打开目标
            data[0] = CTL_DST_CTL_OPEN;
            bridge_send_mod(b, MODULE_DST, dst_packet_ctl, p->dst, stream_id, data, size);
            break;
        }
        case CTL_FORWARD_CTL_ERR: {

            break;
        }
        case 0x02: {
            //查找来源客户端是否存在
            ops_bridge* b = bridge_find(module->manager, p->src_id);
            if (b == NULL) {
                //来源已经不存在
                uint8_t buf[2];
                buf[0] = 0x03;//来自来源的命令
                buf[1] = 0x01;//错误
                bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
                break;
            }
            //发送
            bridge_send_mod(b, MODULE_FORWARD, forward_packet_ctl,service_id, stream_id, data, size);
            break;
        }
        default:
            break;
        }
        break;
    }
    case forward_packet_data: {
        ops_forwards ths = {
            .id = service_id
        };
        ops_forwards* p = RB_FIND(_ops_forwards_tree, &module->forwards, &ths);
        if (p == NULL) {
            uint8_t buf[1];
            buf[0] = CTL_FORWARD_CTL_ERR;
            bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            return;
        }
        //查找目标客户端是否存在
        ops_bridge* b = bridge_find(module->manager, p->dst_id);
        if (b == NULL) {
            uint8_t buf[1];
            buf[0] = CTL_FORWARD_CTL_ERR;
            bridge_send_mod(bridge, MODULE_FORWARD, forward_packet_ctl, service_id, stream_id, buf, sizeof(buf));
            return;
        }
        //发送
        bridge_send_mod(b, MODULE_DST, dst_packet_data, 0, stream_id, data, size);
        break;
    }
    default:
        break;
    }
}

static void on_data_forward_add(ops_module_forward* module, uint32_t id, uint16_t src_id, uint16_t dst_id, uint8_t type, uint16_t src_port, const char* bind, const char* dst, uint16_t dst_port) {
    ops_forwards* forward = malloc(sizeof(*forward));
    if (forward == NULL)
        return;
    //创建目标
    ops_dst_ctrl ctrl;
    ctrl.type = CTL_DST_ADD;
    ctrl.add.src_type = ops_src_type_forward;
    ctrl.add.src_id = src_id;
    ctrl.add.dst_id = dst_id;
    ctrl.add.type = type;
    ctrl.add.bind = bind;
    ctrl.add.dst = dst;
    ctrl.add.dst_port = dst_port;
    uint32_t dsts_id = bridge_mod_ctrl(module->manager, MODULE_DST, &ctrl);
    if (!dsts_id) {
        free(forward);
        return;
    }
    memset(forward, 0, sizeof(*forward));
    forward->id = id;
    forward->src_id = src_id;
    forward->dst_id = dst_id;
    forward->src.sid = id;
    forward->src.type = type;
    forward->src.port = src_port;
    //目标
    forward->dst = dsts_id;
    RB_INSERT(_ops_forwards_tree, &module->forwards, forward);
    //下发到相关通道
    ops_bridge* b = bridge_find(module->manager, src_id);
    if (b) {
        forward_push_src(b, forward);
    }
    b = bridge_find(module->manager, dst_id);
    if (b) {
        //forward_push_dst(b, forward);
    }
}
static void on_data_forward_update(ops_module_forward* module, uint32_t id, uint16_t src_id, uint16_t dst_id, uint8_t type, uint16_t src_port, const char* bind, const char* dst, uint16_t dst_port) {
    ops_forwards ths = {
        .id = id
    };
    //查找ID是否存在
    ops_forwards* forward = RB_FIND(_ops_forwards_tree, &module->forwards, &ths);
    if (forward == NULL) {
        return;
    }
    if (forward->src_id != src_id) {
        //源客户端已修改,通知源客户端删除
        ops_bridge* b = bridge_find(module->manager, forward->src_id);
        if (b) {
            forward_push_del(b, forward->id);
        }
        forward->src_id = src_id;
    }
    if (forward->dst_id != dst_id) {
        //目标客户端已修改,通知原客户端删除
        ops_bridge* b = bridge_find(module->manager, forward->dst_id);
        if (b) {
            forward_push_del(b, forward->id);
        }
        forward->dst_id = dst_id;
    }
    if (forward->src.type != type || forward->src.port != src_port) {
        //源信息修改
        forward->src.type = type;
        forward->src.port = src_port;
        //下发源
        ops_bridge* b = bridge_find(module->manager, forward->src_id);
        if (b) {
            forward_push_src(b, forward);
        }
    }
    /*
    if (forward->dst.type != type || forward->dst.port != dst_port || strcmp(forward->dst.dst, dst) || strcmp(forward->dst.bind, bind)) {
        //目标信息修改
        forward->dst.type = type;
        forward->dst.port = dst_port;
        strncpy(forward->dst.dst, dst, sizeof(forward->dst.dst) - 1);
        forward->dst.dst[sizeof(forward->dst.dst) - 1] = 0;
        strncpy(forward->dst.bind, bind, sizeof(forward->dst.bind) - 1);
        forward->dst.bind[sizeof(forward->dst.bind) - 1] = 0;
        //下发目标
        ops_bridge* b = bridge_find(global, forward->dst_id);
        if (b) {
            //forward_push_dst(b, forward);
        }
    }
    */
}
static void on_data_forward_del(ops_module_forward* module, uint32_t id) {
    ops_forwards ths = {
        .id = id
    };
    //查找ID是否存在
    ops_forwards* forward = RB_FIND(_ops_forwards_tree, &module->forwards, &ths);
    if (forward == NULL) {
        return;
    }
    //通知相关客户端当前服务已移除
    ops_bridge* b = bridge_find(module->manager, forward->src_id);
    if (b) {
        forward_push_del(b, forward->id);
    }
    b = bridge_find(module->manager, forward->dst_id);
    if (b) {
        forward_push_del(b, forward->id);
    }
    RB_REMOVE(_ops_forwards_tree, &module->forwards, forward);
    free(forward);
}
static void forward_ctrl(ops_module_forward* mod, ops_forward_ctrl* ctrl) {
    switch (ctrl->type)
    {
    case ops_forward_ctrl_add: {
        on_data_forward_add(mod, ctrl->add.id, ctrl->add.src_id, ctrl->add.dst_id, ctrl->add.type, ctrl->add.src_port, ctrl->add.bind, ctrl->add.dst, ctrl->add.dst_port);
        break;
    }
    case ops_forward_ctrl_update: {
        on_data_forward_update(mod, ctrl->update.id, ctrl->update.src_id, ctrl->update.dst_id, ctrl->update.type, ctrl->update.src_port, ctrl->update.bind, ctrl->update.dst, ctrl->update.dst_port);
        break;
    }
    case ops_forward_ctrl_del: {
        on_data_forward_del(mod, ctrl->del.id);
        break;
    }
    default:
        break;
    }
}
//创建转发模块
ops_module_forward* forward_module_new(ops_bridge_manager* manager) {
    ops_module_forward* module = (ops_module_forward*)malloc(sizeof(*module));
    if (module == NULL) {
        return NULL;
    }
    memset(module, 0, sizeof(*module));
    RB_INIT(&module->forwards);
    module->manager = manager;
    module->mod.on_load = forward_load;
    module->mod.on_data = forward_data;
    module->mod.on_ctrl = forward_ctrl;
    return module;
}

