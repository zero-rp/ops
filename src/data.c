#include "data.h"

uint16_t data_find_auth_key(const char* key, int key_len) {
    if (key[0] == 'a') {
        return 1;
    }
    if (key[0] == 'b') {
        return 2;
    }
    return 1;
}
