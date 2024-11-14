#ifndef __opc_h_
#define __opc_h_

//配置
typedef struct _opc_config {
    const char* auth_key;       //web api密钥
    const char* server_ip;      //服务器IP
    const char* bind_ip;        //连接服务器使用的本地ip
    uint16_t server_port;       //服务器端口
    uint16_t use_quic;          //是否使用quic
}opc_config;

typedef struct _opc_global opc_global;  //全局对象

const opc_config* opc_get_config(opc_global* global);
uv_loop_t* opc_get_loop(opc_global* global);
void opc_on_close(opc_global* global);
#endif // !__opc_h_
