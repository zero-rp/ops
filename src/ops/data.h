#ifndef _data_h
#define _data_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include "bridge.h"


int data_init(const char* file, ops_global* g, ops_bridge_manager* mgr);

cJSON* data_bridge_get();
int data_bridge_add(const char* key, const char* info);
int data_bridge_del(uint16_t id);
int data_bridge_new_key(uint16_t id, const char* key);

cJSON* data_forward_get();
int data_forward_add(int src_id, int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info);
int data_forward_update(int id, int src_id, int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info);
int data_forward_del(uint32_t id);


cJSON* data_host_get();
int data_host_add(const char* host, int dst_id, int type, const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite, const char* info, uint8_t x_real_ip, uint8_t x_forwarded_for);
int data_host_del(uint32_t id);

cJSON* data_vpc_get();
int data_vpc_add(const char* ipv4, const char* ipv6, const char* info);
int data_vpc_del(uint16_t id);

cJSON* data_member_get();
int data_member_add(uint16_t bid, uint16_t vid, const char* ipv4, const char* ipv6, const char* info);
int data_member_del(uint32_t id);

#endif
