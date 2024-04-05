#ifndef _common_h
#define _common_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

//包类型
enum ops_packet_type
{
    ops_packet_auth = 1,                    //鉴权
    ops_packet_ping,                        //延迟测试和保活
    ops_packet_forward,                     //转发服务
    ops_packet_forward_ctl,                 //转发隧道控制包
    ops_packet_forward_data_remote,         //隧道数据
    ops_packet_forward_data_local,
};
//包定义
typedef struct _ops_packet {
    uint8_t type;                           //包类型
    uint32_t stream_id;                     //流ID
    uint32_t service_id;                    //服务编号
    uint8_t data[];                         //数据
}ops_packet;

//转发服务来源
typedef struct _ops_forward_src {
    uint32_t sid;                            //服务编号
    uint8_t type;                            //服务类型,1 TCP, 2 UDP
    uint16_t port;                           //服务监听端口
}ops_forward_src;
//转发服务目标
typedef struct _ops_forward_dst {
    uint32_t sid;                            //服务编号
    uint8_t type;                            //服务类型,1 TCP, 2 UDP
    uint16_t port;                           //转发的目标端口
    char dst[256];                           //转发的目标地址
}ops_forward_dst;


#endif
