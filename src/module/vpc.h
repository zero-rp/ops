#ifndef __module_vpc_h__
#define __module_vpc_h__


#define MODULE_VPC 2


//包类型
enum vpc_packet_type {
    vpc_packet_vpc,                     //
    vpc_packet_data,                    //数据
};

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



#endif // !__module_dst_h__
