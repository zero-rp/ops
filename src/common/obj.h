#ifndef _OBJ_H
#define _OBJ_H

#include <uv/tree.h>

typedef void (*obj_del) (void*);
typedef struct obj_field {
#ifdef _DEBUG
    RB_ENTRY(obj_field) entry;                       //
    int id;
    int line;
    char* file;
    char* func;
    char* name;
#endif
    int ref;                                        //计数
    obj_del del;                                        //释放
}obj_field;
#ifdef _DEBUG
RB_HEAD(_obj_field_tree, obj_field);


void* obj_make(int size, int offset, char* name, const char* file, int line, const char* func);
void obj_make_ref(obj_field* f, const char* file, int line);
void obj_make_unref(void** p, obj_field* f, const char* file, int line);
void obj_print();
//对象申请
#define obj_new(name, s)  s*name = (s*)obj_make(sizeof(*name), offsetof(s, ref), #name,__FILE__, __LINE__, __func__)
//对象加引用
#define obj_ref(p, tag) p; obj_make_ref(&p->ref, __FILE__, __LINE__)
//对象减引用
#define obj_unref(p, tag) p;  obj_make_unref(&p, &p->ref, __FILE__, __LINE__)

#else

//对象申请
#define obj_new(name, s)  s*name = (s*)malloc(sizeof(*name)); if(name){ memset(name, 0, sizeof(*name)); name->ref.ref = 1; }
//对象加引用
#define obj_ref(p) p; p->ref.ref++;
//对象减引用
#define obj_unref(p) p; p->ref.ref--; if(p->ref.ref<=0){ if(p->ref.del){ p->ref.del(p); } p = NULL; }

#define obj_print()

#endif
#endif
