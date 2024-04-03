#ifndef _data_h
#define _data_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

uint16_t data_find_auth_key(const char* key, int key_len);
void data_get_forward(uint16_t id);


#endif
