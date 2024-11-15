#ifndef __http_h__
#define __http_h__

#include "bridge.h"


typedef struct _ops_http ops_http;

//创建主机模块
ops_http* http_new(ops_global* global, ops_bridge_manager* manager);
void http_host_ctl(ops_http* http, ops_bridge* bridge, uint32_t stream_id, uint8_t* data, int size);
void http_host_data(ops_http* http, uint32_t stream_id, uint8_t* data, int size);
void http_host_add(ops_http* http, uint32_t id, const char* src_host, uint16_t dst_id, uint8_t type, 
    const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite, 
    uint8_t x_real_ip, uint8_t x_forwarded_for);
void http_host_del(ops_http* http, const char* h);
#endif // !__http_h__
