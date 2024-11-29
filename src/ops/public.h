#ifndef __public_h__
#define __public_h__
#include "bridge.h"

typedef struct _ops_public ops_public;

//创建主机模块
ops_public* public_new(ops_global* global, ops_bridge_manager* manager);
void publib_ctl(ops_public* public, ops_bridge* bridge, uint32_t stream_id, uint8_t* data, int size);
void public_data(ops_public* http, uint32_t stream_id, uint8_t* data, int size);
void public_add(ops_public* public, uint32_t id, uint16_t port, uint16_t dst_id, uint8_t type, const char* bind, const char* dst, uint16_t dst_port);
void public_del(ops_public* http, const char* h);

#endif // !__public_h__
