#ifndef __ops_h__
#define __ops_h__
#include <uv.h>

//配置
typedef struct _ops_config {
    uint16_t web_port;          //web管理端口
    const char* web_password;   //web界面管理密码
    const char* web_username;   //web界面管理账号
    const char* web_base_url;   //web管理主路径, 用于将web管理置于代理子路径后面
    uint16_t bridge_port;       //服务端客户端通信端口
    uint16_t https_proxy_port;  //域名代理https代理监听端口
    uint16_t http_proxy_port;   //域名代理http代理监听端口
    const char* auth_key;       //web api密钥
    const char* admin_user;
    const char* admin_pass;
    const char* db_file;
    const char* cert_file;		//证书文件
    const char* key_file;	    //私钥文件
    uint8_t rand_cert;          //随机证书
}ops_config;

typedef struct _ops_global ops_global;
typedef struct _ops_http ops_http;
typedef struct _ops_bridge_manager ops_bridge_manager;
typedef struct _ops_web ops_web;
typedef struct _ops_public ops_public;
//获取配置
const ops_config* opc_get_config(ops_global* global);
//
uv_loop_t* ops_get_loop(ops_global* global);
ops_http* ops_get_http(ops_global* global);
ops_public* ops_get_public(ops_global* global);
ops_bridge_manager* ops_get_bridge_manager(ops_global* global);
//ops_web* ops_get_web(ops_global* global);
#endif // !__ops_h__
