#include "databuffer.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void messagepool_free(struct messagepool* pool) {
    struct messagepool_list* p = pool->pool;
    while (p) {
        struct messagepool_list* tmp = p;
        p = p->next;
        free(tmp);
    }
    pool->pool = NULL;
    pool->freelist = NULL;
}

static inline void _return_message(struct databuffer* db, struct messagepool* mp) {
    struct message* m = db->head;
    if (m->next == NULL) {
        assert(db->tail == m);
        db->head = db->tail = NULL;
    }
    else {
        db->head = m->next;
    }
    free(m->buffer);
    m->buffer = NULL;
    m->size = 0;
    m->next = mp->freelist;
    mp->freelist = m;
}

void databuffer_read(struct databuffer* db, struct messagepool* mp, char* buffer, int sz) {
    assert(db->size >= sz);
    db->size -= sz;
    for (;;) {
        struct message* current = db->head;
        int bsz = current->size - db->offset;
        if (bsz > sz) {
            memcpy(buffer, current->buffer + db->offset, sz);
            db->offset += sz;
            return;
        }
        if (bsz == sz) {
            memcpy(buffer, current->buffer + db->offset, sz);
            db->offset = 0;
            _return_message(db, mp);
            return;
        }
        else {
            memcpy(buffer, current->buffer + db->offset, bsz);
            _return_message(db, mp);
            db->offset = 0;
            buffer += bsz;
            sz -= bsz;
        }
    }
}

void databuffer_discard(struct databuffer* db, struct messagepool* mp, int sz) {
    assert(db->size >= sz);
    db->size -= sz;
    for (;;) {
        struct message* current = db->head;
        int bsz = current->size - db->offset;
        if (bsz > sz) {
            db->offset += sz;
            return;
        }
        if (bsz == sz) {
            db->offset = 0;
            _return_message(db, mp);
            return;
        }
        else {
            _return_message(db, mp);
            db->offset = 0;
            sz -= bsz;
        }
    }
}

void databuffer_push(struct databuffer* db, struct messagepool* mp, char* data, int sz) {
    struct message* m;
    if (mp->freelist) {
        m = mp->freelist;
        mp->freelist = m->next;
    }
    else {
        struct messagepool_list* mpl = malloc(sizeof(*mpl));
        struct message* temp = mpl->pool;
        int i;
        for (i = 1; i < MESSAGEPOOL; i++) {
            temp[i].buffer = NULL;
            temp[i].size = 0;
            temp[i].next = &temp[i + 1];
        }
        temp[MESSAGEPOOL - 1].next = NULL;
        mpl->next = mp->pool;
        mp->pool = mpl;
        m = &temp[0];
        mp->freelist = &temp[1];
    }
    m->buffer = data;
    m->size = sz;
    m->next = NULL;
    db->size += sz;
    if (db->head == NULL) {
        assert(db->tail == NULL);
        db->head = db->tail = m;
    }
    else {
        db->tail->next = m;
        db->tail = m;
    }
}

int databuffer_readheader(struct databuffer* db, struct messagepool* mp, int header_size) {
    if (db->header == 0) {
        // parser header (2 or 4)
        int h = header_size < 0 ? header_size : 0;
        header_size = header_size < 0 ? -header_size : header_size;
        if (db->size < header_size) {
            return -1;
        }
        uint8_t plen[4];
        databuffer_read(db, mp, (char*)plen, header_size);
        // big-endian
        if (header_size == 2) {
            db->header = (plen[0] << 8 | plen[1]) + h;
        }
        else {
            db->header = (plen[0] << 24 | plen[1] << 16 | plen[2] << 8 | plen[3]) + h;
        }
    }
    if (db->size < db->header)
        return -1;
    return db->header;
}

void databuffer_clear(struct databuffer* db, struct messagepool* mp) {
    while (db->head) {
        _return_message(db, mp);
    }
    memset(db, 0, sizeof(*db));
}

