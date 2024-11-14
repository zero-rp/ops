#ifndef __module_forward_h__
#define __module_forward_h__

#define MODULE_FORWARD 0  

//包类型
enum forward_packet_type{
    forward_packet_forward,             //转发
    forward_packet_ctl,                 //转发控制
    forward_packet_data,                //转发数据
};

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

#endif // !__module_forward_h__
