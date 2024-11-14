#ifndef __module_dst_h__
#define __module_dst_h__


#define MODULE_DST 1


//包类型
enum dst_packet_type {
    dst_packet_dst,                     //目标
    dst_packet_ctl,                     //目标控制
    dst_packet_data,                    //目标数据
};


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


#endif // !__module_dst_h__
