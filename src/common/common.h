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
    ops_packet_mod,                         //模块包
    ops_packet_plugin,                      //插件包
    ops_packet_info,                        //上报信息
};
//鉴权
#define CTL_AUTH_ERR    0x01                //鉴权失败
#define CTL_AUTH_OK     0x02                //鉴权成功
#define CTL_AUTH_ONLINE 0x03                //鉴权成功,但已在线
//包定义
typedef struct _ops_packet {
    uint8_t type;                           //包类型
    union {
        struct {
            uint8_t mod;                    //模块id
            uint8_t type;                   //包类型
            uint32_t stream_id;             //流ID
            uint32_t service_id;            //服务编号
            uint8_t data[];                 //数据
        }mod;
        uint8_t data[];                         //数据
    };
}ops_packet;




#pragma pack(pop)   // 恢复之前的对齐状态
#endif
