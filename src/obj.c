#include <stdlib.h>
#include "obj.h"

#ifdef _DEBUG
static struct _obj_field_tree _obj = { 0 };
static int _obj_id = 0;

static int _obj_field_compare(obj_field* w1, obj_field* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_obj_field_tree, obj_field, entry, _obj_field_compare)

void* obj_make(int size, int offset, char* name, const char* file, int line, const char* func) {
    char* p = malloc(size);
    if (p == NULL) {
        return NULL;
    }
    memset(p, 0, size);
    obj_field* f = (obj_field*)(p + offset);
    f->ref = 1;
    f->id = _obj_id++;
    f->line = line;
    f->file = strdup(file);
    f->name = strdup(name);
    f->func = strdup(func);
    RB_INSERT(_obj_field_tree, &_obj, f);
    return p;
}

void obj_make_ref(obj_field* f, const char* file, int line) {

    f->ref++;
}

void obj_make_unref(void** p, obj_field* f, const char* file, int line) {
    f->ref--;
    if (f->ref > 0) {
        return;
    }
    if (f->del) {
        f->del(*p);
    }
    RB_REMOVE(_obj_field_tree, &_obj, f);
    free(*p);
    *p = NULL;
}

void obj_print() {
    obj_field* f = NULL;
    RB_FOREACH(f, _obj_field_tree, &_obj) {
        printf("Id:%d,Name:%s,Ref:%d,File:%s,Line:%d,Func:%s\r\n", f->id, f->name, f->ref, f->file, f->line, f->func);
    }
    printf("--------------------------------------------------------------------------------------\r\n");
}


#endif
