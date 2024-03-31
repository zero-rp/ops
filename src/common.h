#ifndef _common_h
#define _common_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

//包类型
enum ops_packet_type
{
    ops_packet_auth = 1,        //鉴权
    ops_packet_service,         //新服务
};
//包定义
typedef struct _ops_packet {
    uint8_t  type;              //包类型
    uint32_t stream_id;                     //流ID
    char data[];                            //数据
}ops_packet;



#endif
