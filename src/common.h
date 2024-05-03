#ifndef _common_h
#define _common_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#pragma pack(push)  // 保存当前对齐状态
#pragma pack(1)     // 设置一字节对齐
//包类型
enum ops_packet_type
{
    ops_packet_auth = 1,                    //鉴权
    ops_packet_ping,                        //延迟测试和保活
    ops_packet_info,                        //上报信息
    ops_packet_plugin,
    ops_packet_dst,                         //目标
    ops_packet_dst_ctl,                     //目标控制
    ops_packet_dst_data,                    //目标数据
    ops_packet_forward,                     //转发
    ops_packet_forward_ctl,                 //转发控制
    ops_packet_forward_data,                //转发数据
    ops_packet_vpc,                         //局域网服务
    ops_packet_vpc_data,
};
//鉴权
#define CTL_AUTH_ERR    0x01                //鉴权失败
#define CTL_AUTH_OK     0x02                //鉴权成功
#define CTL_AUTH_ONLINE 0x03                //鉴权成功,但已在线
//包定义
typedef struct _ops_packet {
    uint8_t type;                           //包类型
    uint32_t stream_id;                     //流ID
    uint32_t service_id;                    //服务编号
    uint8_t data[];                         //数据
}ops_packet;
//目标定义
#define CTL_DST_ADD  0x01                       //添加目标
#define CTL_DST_DEL  0x02                       //添加目标
#define CTL_DST_CTL_OPEN    0x01                //打开目标
#define CTL_DST_CTL_SUC     0x02                //打开成功
#define CTL_DST_CTL_ERR     0x03                //打开目标
typedef struct _ops_dst {
    uint8_t stype;                           //源服务类型
    uint32_t sid;                            //服务编号
    uint8_t type;                            //服务类型,1 TCP, 2 UDP
    char bind[256];                          //绑定的本地出口地址
    uint16_t port;                           //转发的目标端口
    char dst[256];                           //转发的目标地址
}ops_dst;
//转发服务
#define CTL_FORWARD_ADD  0x01                   //添加
#define CTL_FORWARD_DEL  0x02                   //删除
#define CTL_FORWARD_CTL_OPEN    0x01            //打开目标
#define CTL_FORWARD_CTL_SUC     0x02            //打开目标
#define CTL_FORWARD_CTL_ERR     0x03            //打开目标
#define FORWARD_TYPE_TCP        0x01
#define FORWARD_TYPE_UDP        0x02
#define FORWARD_TYPE_SOCKS5     0x03
#define FORWARD_TYPE_HTTP       0x04
//转发服务来源
typedef struct _ops_forward {
    uint32_t sid;                            //服务编号
    uint8_t type;                            //服务类型,1 TCP, 2 UDP, 3 SOCK5, 4 HTTP
    uint16_t port;                           //服务监听端口
}ops_forward;
//网络成员
#define CTL_MEMBER_ADD  0x01                //添加
#define CTL_MEMBER_DEL  0x02                //删除
typedef struct _ops_member {
    uint16_t vid;                           //VPC编号
    uint32_t id;                            //成员编号
    uint8_t ipv4[4];                        //ipv4地址
    uint8_t prefix_v4;                      //ipv4前缀
    uint8_t ipv6[16];                       //ipv6地址
    uint8_t prefix_v6;                      //ipv6前缀
}ops_member;


#pragma pack(pop)   // 恢复之前的对齐状态
#endif
