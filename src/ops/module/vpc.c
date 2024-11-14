#include <stdlib.h>
#include <uv.h>
#include <uv/tree.h>
#include <common/sds.h>

#include "vpc.h"
//VPC网络
typedef struct _ops_vpc {
    RB_ENTRY(_ops_vpc) entry;            //
    uint16_t id;                             //网络编号
    struct in_addr ipv4;                         //ipv4网段
    uint8_t prefix_v4;                      //ipv4前缀
    struct in6_addr ipv6;                        //ipv6网段
    uint8_t prefix_v6;                      //ipv6前缀
}ops_vpc;
RB_HEAD(_ops_vpc_tree, _ops_vpc);
//VPC成员
typedef struct _ops_members {
    RB_ENTRY(_ops_members) entry;                //
    uint16_t bid;                               //客户ID
    uint16_t vid;                               //VPCID
    ops_vpc* vpc;                               //关联的VPC
    uint32_t id;                                //成员编号
    struct in_addr ipv4;                        //ipv4地址
    uint8_t prefix_v4;                      //ipv4前缀
    struct in6_addr ipv6;                       //ipv6地址
    uint8_t prefix_v6;                      //ipv6前缀
}ops_members;
RB_HEAD(_ops_members_tree, _ops_members);
//VPC路由
typedef struct _ops_route_v4 {
    RB_ENTRY(_ops_route_v4) entry;              //
    uint16_t id;                                //客户ID
    uint32_t mid;                               //成员ID
    struct in_addr ip;                              //地址
}ops_route_v4;
RB_HEAD(_ops_route_v4_tree, _ops_route_v4);
typedef struct _ops_route_v6 {
    RB_ENTRY(_ops_route_v6) entry;              //
    uint16_t id;                                //客户ID
    uint32_t mid;                               //成员ID
    struct in6_addr ip;                             //地址
}ops_route_v6;
RB_HEAD(_ops_route_v6_tree, _ops_route_v6);

typedef struct _ops_module_vpc {
    ops_module mod;                         //模块
    ops_bridge_manager* manager;            //管理器
    struct _ops_vpc_tree vpc;               //虚拟网络
    struct _ops_members_tree members;       //虚拟网络成员
    struct _ops_route_v4_tree route_v4;     //IPv4路由表
    struct _ops_route_v6_tree route_v6;     //IPv6路由表
} ops_module_vpc;


static int _ops_vpc_compare(ops_vpc* w1, ops_vpc* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_vpc_tree, _ops_vpc, entry, _ops_vpc_compare)
static int _ops_members_compare(ops_members* w1, ops_members* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_members_tree, _ops_members, entry, _ops_members_compare)
static int _ops_route_v4_compare(ops_route_v4* w1, ops_route_v4* w2) {
    if (*(uint32_t*)(&w1->ip) < *(uint32_t*)(&w2->ip)) return -1;
    if (*(uint32_t*)(&w1->ip) > *(uint32_t*)(&w2->ip)) return 1;
    return 0;
}
RB_GENERATE_STATIC(_ops_route_v4_tree, _ops_route_v4, entry, _ops_route_v4_compare)
static int _ops_route_v6_compare(ops_route_v6* w1, ops_route_v6* w2) {
    for (int i = 0; i < 16; i++) {
        if (w1->ip.s6_addr[i] != w2->ip.s6_addr[i]) {
            return w1->ip.s6_addr[i] > w2->ip.s6_addr[i] ? 1 : -1;
        }
    }
    return 0;
}
RB_GENERATE_STATIC(_ops_route_v6_tree, _ops_route_v6, entry, _ops_route_v6_compare)


static void cidr_to_netmask_v4(int prefix, struct in_addr* netmask) {
    netmask->s_addr = htonl(~((1 << (32 - prefix)) - 1));
}
static void cidr_to_netmask_v6(int prefix, struct in6_addr* netmask) {
    for (int i = 0; i < 16; i++) {
        if (prefix > 8) {
            netmask->s6_addr[i] = 0xFF;
            prefix -= 8;
        }
        else {
            netmask->s6_addr[i] = (0xFF << (8 - prefix)) & 0xFF;
            prefix = 0;
        }
    }
}
static void cidr_to_network_v4(const char* ip, int prefix, struct in_addr* network) {
    struct in_addr netmask;
    cidr_to_netmask_v4(prefix, &netmask);
    network->s_addr = inet_addr(ip) & netmask.s_addr;
}
static void cidr_to_network_v6(const char* ip, int prefix, struct in6_addr* network) {
    struct in6_addr netmask;
    cidr_to_netmask_v6(prefix, &netmask);
    inet_pton(AF_INET6, ip, network);
    for (int i = 0; i < 16; i++) {
        network->s6_addr[i] &= netmask.s6_addr[i];
    }
}
//数据处理
static void _data(ops_module_vpc* module, ops_bridge* bridge, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    uint8_t ip_version = data[0] >> 4;
    uint16_t bid = 0;
    uint32_t mid = 0;
    switch (ip_version)
    {
    case 4: {
        ops_route_v4 v4 = { 0 };
        memcpy(&v4.ip, &data[16], sizeof(v4.ip));
        ops_route_v4* r = RB_FIND(_ops_route_v4_tree, &module->route_v4, &v4);
        if (!r) {
            return;
        }
        bid = r->id;
        mid = r->mid;
        break;
    }
    case 6: {
        ops_route_v6 v6 = { 0 };
        memcpy(&v6.ip, &data[24], sizeof(v6.ip));
        ops_route_v6* r = RB_FIND(_ops_route_v6_tree, &module->route_v6, &v6);
        if (!r) {
            return;
        }
        bid = r->id;
        mid = r->mid;
        break;
    }
    default:
        return;
    }
    //查找客户端
    ops_bridge* b = bridge_find(module->manager, bid);
    if (!b) {
        return;
    }
    //转发
    bridge_send_mod(b, MODULE_VPC, vpc_packet_data, service_id, mid, data, size);
}
static void vpc_data(ops_module_vpc* module, ops_bridge* bridge, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case vpc_packet_data:
        _data(module, bridge, stream_id, service_id, data, size);
        break;
    default:
        break;
    }
}
//加载
static void vpc_load(ops_module_vpc* module, ops_bridge* bridge) {
    sds pack = sdsnewlen(NULL, 5);//预留数量和指令
    //查询相关的vpc节点
    pack = sdsnewlen(NULL, 5);//预留数量和指令
    pack[0] = CTL_MEMBER_ADD;
    int count = 0;
    ops_members* mc = NULL;
    RB_FOREACH(mc, _ops_members_tree, &module->members) {
        if (mc->bid == bridge_id(bridge)) {
            ops_member mem;
            mem.id = htonl(mc->id);
            mem.vid = htons(mc->vpc->id);
            memcpy(mem.ipv4, &mc->ipv4, sizeof(mem.ipv4));
            mem.prefix_v4 = mc->prefix_v4;
            memcpy(mem.ipv6, &mc->ipv6, sizeof(mem.ipv6));
            mem.prefix_v6 = mc->prefix_v6;
            pack = sdscatlen(pack, &mem, sizeof(mem));
            count++;
        }
    }
    *(uint32_t*)(&pack[1]) = htonl(count);
    //下发主机服务
    if (count > 0) {
        bridge_send_mod(bridge, MODULE_VPC, vpc_packet_vpc, 0, 0, pack, sdslen(pack));
    }
    sdsfree(pack);
}
//控制
//成员事件
static void on_data_member_add(ops_module_vpc* module, uint32_t id, uint16_t bid, uint16_t vid, const char* ipv4, const char* ipv6) {
    //查找vpc
    ops_vpc the = {
        .id = vid
    };
    ops_vpc* v = RB_FIND(_ops_vpc_tree, &module->vpc, &the);
    if (!v) {
        //没有对应的vpc
        return;
    }
    //
    ops_members* mem = malloc(sizeof(*mem));
    if (mem == NULL)
        return;
    memset(mem, 0, sizeof(*mem));
    mem->id = id;
    mem->bid = bid;
    mem->vpc = v;
    //IPV4
    struct sockaddr_in addr;
    uv_ip4_addr(ipv4, 0, &addr);
    memcpy(&mem->ipv4, &addr.sin_addr, sizeof(mem->ipv4));
    mem->prefix_v4 = v->prefix_v4;
    //IPV6
    struct sockaddr_in6 addr6;
    uv_ip6_addr(ipv6, 0, &addr6);
    memcpy(&mem->ipv6, &addr6.sin6_addr, sizeof(mem->ipv6));
    mem->prefix_v6 = v->prefix_v6;
    //记录
    RB_INSERT(_ops_members_tree, &module->members, mem);
    //生成路由
    ops_route_v4* v4 = (ops_route_v4*)malloc(sizeof(*v4));
    if (!v4) {
        return;
    }
    memset(v4, 0, sizeof(*v4));
    v4->id = bid;
    v4->mid = id;
    memcpy(&v4->ip, &addr.sin_addr, sizeof(v4->ip));
    RB_INSERT(_ops_route_v4_tree, &module->route_v4, v4);

    ops_route_v6* v6 = (ops_route_v6*)malloc(sizeof(*v6));
    if (!v6) {
        return;
    }
    memset(v6, 0, sizeof(*v6));
    v6->id = bid;
    v6->mid = id;
    memcpy(&v6->ip, &addr6.sin6_addr, sizeof(v6->ip));
    RB_INSERT(_ops_route_v6_tree, &module->route_v6, v6);
    //下发成员
    ops_bridge* bridge = bridge_find(module->manager, bid);
    if (!bridge)
        return;
    char buf[1 + 4 + sizeof(ops_member)];
    buf[0] = CTL_MEMBER_ADD;
    *(uint32_t*)(&buf[1]) = htonl(1);
    ops_member _mem;
    _mem.id = htonl(id);
    _mem.vid = htons(vid);
    memcpy(_mem.ipv4, &v4->ip, sizeof(_mem.ipv4));
    _mem.prefix_v4 = v->prefix_v4;
    memcpy(_mem.ipv6, &v6->ip, sizeof(_mem.ipv6));
    _mem.prefix_v6 = v->prefix_v6;
    memcpy(&buf[5], &_mem, sizeof(_mem));
    bridge_send_mod(bridge, MODULE_VPC, vpc_packet_vpc, 0, 0, buf, sizeof(buf));
}
static void on_data_member_del(ops_module_vpc* module, uint32_t id) {
    ops_members the = {
       .id = id
    };
    ops_members* mem = RB_FIND(_ops_members_tree, &module->members, &the);
    if (mem == NULL) {
        return;
    }
    //通知
    ops_bridge* bridge = bridge_find(module->manager, mem->bid);
    if (bridge) {
        char buf[1 + 4];
        buf[0] = CTL_MEMBER_DEL;//删除指令
        *(uint32_t*)(&buf[1]) = htonl(id);
        bridge_send_mod(bridge, MODULE_VPC, vpc_packet_vpc, 0, 0, buf, sizeof(buf));
    }
    RB_REMOVE(_ops_members_tree, &module->members, mem);
    free(mem);
}
//事件
static void on_data_vpc_add(ops_module_vpc* module, uint16_t id, const char* ipv4, const char* ipv6) {
    ops_vpc* vpc = malloc(sizeof(*vpc));
    if (vpc == NULL)
        return;
    memset(vpc, 0, sizeof(*vpc));
    vpc->id = id;

    int prefix;
    char cidr[INET6_ADDRSTRLEN + 6] = { 0 };
    char* ip, * subnet;
    // IPv4
    strncpy(cidr, ipv4, sizeof(cidr));
    ip = strtok(cidr, "/");
    if (ip) {
        subnet = strtok(NULL, "/");
        if (subnet) {
            prefix = atoi(subnet);
            vpc->prefix_v4 = prefix;                      //前缀
            cidr_to_network_v4(ip, prefix, &vpc->ipv4);
        }
    }
    // IPv6
    cidr[0] = 0;
    strncpy(cidr, ipv6, sizeof(cidr));
    ip = strtok(cidr, "/");
    if (ip) {
        subnet = strtok(NULL, "/");
        if (subnet) {
            prefix = atoi(subnet);
            vpc->prefix_v6 = prefix;                      //前缀
            cidr_to_network_v6(ip, prefix, &vpc->ipv6);
        }
    }
    RB_INSERT(_ops_vpc_tree, &module->vpc, vpc);
}
static void on_data_vpc_del(ops_module_vpc* module, uint16_t id) {
    ops_vpc the = {
           .id = id
    };
    ops_vpc* vpc = RB_FIND(_ops_vpc_tree, &module->vpc, &the);
    if (vpc == NULL) {
        return;
    }
    //移除关联的所有成员
    ops_members* c = NULL;
    ops_members* cc = NULL;
    RB_FOREACH_SAFE(c, _ops_members_tree, &module->members, cc) {
        if (c->vid == id) {
            on_data_member_del(module, c->id);
        }
        cc = NULL;
    }
    RB_REMOVE(_ops_vpc_tree, &module->vpc, vpc);
    free(vpc);
}
static void vpc_ctrl(ops_module_vpc* module, ops_vpc_ctrl* ctrl) {
    switch (ctrl->type)
    {
    case ops_vpc_ctrl_vpc_add:
        on_data_vpc_add(module, ctrl->vpc_add.id, ctrl->vpc_add.ipv4, ctrl->vpc_add.ipv6);
        break;
    case ops_vpc_ctrl_vpc_del:
        on_data_vpc_del(module, ctrl->vpc_del.id);
        break;
    case ops_vpc_ctrl_member_add:
        on_data_member_add(module, ctrl->member_add.id, ctrl->member_add.bid, ctrl->member_add.vid, ctrl->member_add.ipv4, ctrl->member_add.ipv6);
        break;
    case ops_vpc_ctrl_member_del:
        on_data_member_del(module, ctrl->member_del.id);
        break;
    default:
        break;
    }
}
//创建目标模块
ops_module_vpc* vpc_module_new(ops_bridge_manager* manager) {
    ops_module_vpc* mod = malloc(sizeof(*mod));
    if (!mod)
        return NULL;
    memset(mod, 0, sizeof(*mod));
    mod->manager = manager;
    RB_INIT(&mod->vpc);
    RB_INIT(&mod->members);
    mod->mod.on_load = vpc_load;
    mod->mod.on_data = vpc_data;
    mod->mod.on_ctrl = vpc_ctrl;
    return mod;
}

