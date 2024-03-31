#ifndef _databuffer_h
#define _databuffer_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MESSAGEPOOL 1023

struct message {
    char* buffer;
    int size;
    struct message* next;
};

struct databuffer {
    int header;
    int offset;
    int size;
    struct message* head;
    struct message* tail;
};

struct messagepool_list {
    struct messagepool_list* next;
    struct message pool[MESSAGEPOOL];
};

struct messagepool {
    struct messagepool_list* pool;
    struct message* freelist;
};

void messagepool_free(struct messagepool* pool);
void databuffer_read(struct databuffer* db, struct messagepool* mp, char* buffer, int sz);
void databuffer_discard(struct databuffer* db, struct messagepool* mp, int sz);
void databuffer_push(struct databuffer* db, struct messagepool* mp, char* data, int sz);
int databuffer_readheader(struct databuffer* db, struct messagepool* mp, int header_size);
#define databuffer_reset(db) ((db))->header = 0
void databuffer_clear(struct databuffer* db, struct messagepool* mp);

#endif
