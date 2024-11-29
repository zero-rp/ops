#include <stdio.h>
#include "data.h"
#include <sqlite3.h>
#include "bridge.h"
#include "http.h"
#include "public.h"
#include "module/forward.h"
#include "module/vpc.h"

static sqlite3* db = NULL;
ops_bridge_manager* manager = NULL;
ops_global* global = NULL;

static int _key_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    ops_mgr_ctrl ctrl;
    ctrl.type = ops_mgr_ctrl_key_add;
    ctrl.add.id = atoi(argv[0]);
    ctrl.add.k = argv[1];
    bridge_mgr_ctrl(manager, &ctrl);
    return 0;
}
static int _forward_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    ops_forward_ctrl ctrl;
    ctrl.type = ops_forward_ctrl_add;
    ctrl.add.id = atoi(argv[0]);
    ctrl.add.src_id = atoi(argv[1]);
    ctrl.add.dst_id = atoi(argv[2]);
    ctrl.add.type = atoi(argv[3]);
    ctrl.add.src_port = atoi(argv[4]);
    ctrl.add.bind = argv[5];
    ctrl.add.dst = argv[6];
    ctrl.add.dst_port = atoi(argv[7]);
    bridge_mod_ctrl(manager, MODULE_FORWARD, &ctrl);
    return 0;
}
static int _public_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    public_add(ops_get_public(global), atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], atoi(argv[6]));
    return 0;
}
static int _host_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    http_host_add(ops_get_http(global), atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], atoi(argv[6]), argv[7], atoi(argv[9]), atoi(argv[10]));
    return 0;
}
static int _vpc_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    ops_vpc_ctrl ctrl;
    ctrl.type = ops_vpc_ctrl_vpc_add;
    ctrl.member_add.id = atoi(argv[0]);
    ctrl.member_add.ipv4 = argv[1];
    ctrl.member_add.ipv6 = argv[2];
    bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
    return 0;
}
static int _member_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    ops_vpc_ctrl ctrl;
    ctrl.type = ops_vpc_ctrl_member_add;
    ctrl.member_add.id = atoi(argv[0]);
    ctrl.member_add.bid = atoi(argv[1]);
    ctrl.member_add.vid = atoi(argv[2]);
    ctrl.member_add.ipv4 = argv[3];
    ctrl.member_add.ipv6 = argv[4];
    bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
    return 0;
}
//初始化
int data_init(const char* file, ops_global* g, ops_bridge_manager* mgr) {
    sqlite3_initialize();
    int ret = sqlite3_open_v2(file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    manager = mgr;
    global = g;
    //初始化
    char* zErrMsg = 0;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS bridge (id INTEGER PRIMARY KEY AUTOINCREMENT, key VARCHAR(64) NOT NULL, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX key ON bridge (key);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS forward (id INTEGER PRIMARY KEY AUTOINCREMENT,src_id INTEGER NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, src_port INTEGER NOT NULL,bind TEXT, dst TEXT NOT NULL, dst_port INTEGER NOT NULL, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS host (id INTEGER PRIMARY KEY AUTOINCREMENT, host VARCHAR(256) NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, bind TEXT, dst TEXT NOT NULL, dst_port INTEGER NOT NULL, host_rewrite TEXT, info TEXT, x_real_ip INTEGER NOT NULL DEFAULT 1, x_forwarded_for INTEGER NOT NULL DEFAULT 1); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS vpc (id INTEGER PRIMARY KEY AUTOINCREMENT, ipv4 TEXT, ipv6 TEXT, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS public (id INTEGER PRIMARY KEY AUTOINCREMENT, port INTEGER NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, bind TEXT, dst TEXT NOT NULL, dst_port INTEGER NOT NULL, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX vipv4 ON vpc (ipv4);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX vipv6 ON vpc (ipv6);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS member (id INTEGER PRIMARY KEY AUTOINCREMENT, bid INTEGER NOT NULL, vid INTEGER NOT NULL, ipv4 TEXT, ipv6 TEXT, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX mipv4 ON member (ipv4);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX mipv6 ON member (ipv6);", NULL, 0, &zErrMsg);
    //升级
    sqlite3_exec(db, "ALTER TABLE host ADD COLUMN x_real_ip INTEGER NOT NULL DEFAULT 1;", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "ALTER TABLE host ADD COLUMN x_forwarded_for INTEGER NOT NULL DEFAULT 1;", NULL, 0, &zErrMsg);
    //加载数据
    sqlite3_exec(db, "SELECT id, key FROM bridge;", _key_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM forward;", _forward_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM public;", _public_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM host;", _host_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM vpc;", _vpc_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM member;", _member_callback, NULL, &zErrMsg);
    return 0;
}

//获取转发列表
static int _get_json_callback(void* argument, int argc, char** argv, char** azColName) {
    cJSON* list = (cJSON*)argument;
    cJSON* item = cJSON_CreateObject();
    for (size_t i = 0; i < argc; i++) {
        cJSON_AddStringToObject(item, azColName[i], argv[i]);
    }
    cJSON_AddItemToArray(list, item);
    return 0;
}

cJSON* data_bridge_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM bridge;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_bridge_add(const char* key, const char* info) {
    char sql[256] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO bridge (`key`, `info`)VALUES(\"%s\",\"%s\");", key, info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            ops_mgr_ctrl ctrl;
            ctrl.type = ops_mgr_ctrl_key_add;
            ctrl.add.id = id;
            ctrl.add.k = key;
            bridge_mgr_ctrl(manager, &ctrl);
            return 0;
        }
    }
    return -1;
}
int data_bridge_del(uint16_t id) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    char key[33] = { 0 };
    snprintf(sql, sizeof(sql), "SELECT key FROM bridge WHERE id = %d;", id);
    cJSON* list = cJSON_CreateArray();
    if (sqlite3_exec(db, sql, _get_json_callback, list, &zErrMsg) == SQLITE_OK) {
        if (cJSON_GetArraySize(list) != 1) {
            cJSON_free(list);
            return -1;
        }
        cJSON* item = cJSON_GetArrayItem(list, 0);
        if (!item) {
            cJSON_free(list);
            return -1;
        }
        cJSON* k = cJSON_GetObjectItem(item, "key");
        if (!k || !k->valuestring) {
            cJSON_free(list);
            return -1;
        }
        strncpy(key, k->valuestring, 32);
    }
    cJSON_free(list);
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM bridge WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_mgr_ctrl ctrl;
            ctrl.type = ops_mgr_ctrl_key_del;
            ctrl.del.k = key;
            bridge_mgr_ctrl(manager, &ctrl);
            return 0;
        }
    }
    return -1;
}
int data_bridge_new_key(uint16_t id, const char* key) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    //删除
    snprintf(sql, sizeof(sql), "UPDATE bridge SET key = \"%s\" WHERE id = %d;", key, id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_mgr_ctrl ctrl;
            ctrl.type = ops_mgr_ctrl_key_new;
            ctrl.new.id = id;
            ctrl.new.k = key;
            bridge_mgr_ctrl(manager, &ctrl);
            return 0;
        }
    }
    return -1;
}

cJSON* data_forward_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM forward;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_forward_add(int src_id, int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO forward (`src_id`, `dst_id`, `type`, `src_port`, `bind`, `dst`, `dst_port`, `info`)VALUES(%d, %d, %d, %d, \"%s\", \"%s\", %d, \"%s\");",
        src_id, dst_id, type, src_port, bind, dst, dst_port, info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            ops_forward_ctrl ctrl;
            ctrl.type = ops_forward_ctrl_add;
            ctrl.add.id = id;
            ctrl.add.src_id = src_id;
            ctrl.add.dst_id = dst_id;
            ctrl.add.type = type;
            ctrl.add.src_port = src_port;
            ctrl.add.bind = bind;
            ctrl.add.dst = dst;
            ctrl.add.dst_port = dst_port;
            bridge_mod_ctrl(manager, MODULE_FORWARD, &ctrl);
            return 0;
        }
    }
    return -1;
}
int data_forward_update(int id, int src_id, int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql),
        "UPDATE forward SET `src_id` = %d, `dst_id` = %d, `type` = %d, `src_port` = %d, `bind` = \"%s\", `dst` = \"%s\", `dst_port` = %d, `info` = \"%s\" WHERE id = %d",
        src_id, dst_id, type, src_port, bind, dst, dst_port, info ? info : "", id);
    //更新
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_forward_ctrl ctrl;
            ctrl.type = ops_forward_ctrl_update;
            ctrl.update.id = id;
            ctrl.update.src_id = src_id;
            ctrl.update.dst_id = dst_id;
            ctrl.update.type = type;
            ctrl.update.src_port = src_port;
            ctrl.update.bind = bind;
            ctrl.update.dst = dst;
            ctrl.update.dst_port = dst_port;
            bridge_mod_ctrl(manager, MODULE_FORWARD, &ctrl);
            return 0;
        }
    }
}
int data_forward_del(uint32_t id) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM forward WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_forward_ctrl ctrl;
            ctrl.type = ops_forward_ctrl_del;
            ctrl.del.id = id;
            bridge_mod_ctrl(manager, MODULE_FORWARD, &ctrl);
            return 0;
        }
    }
    return -1;
}

cJSON* data_public_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM public;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_public_add(int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO public (`dst_id`, `type`, `port`, `bind`, `dst`, `dst_port`, `info`)VALUES(%d, %d, %d, \"%s\", \"%s\", %d, \"%s\");",
        dst_id, type, src_port, bind, dst, dst_port, info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            return 0;
        }
    }
    return -1;
}
int data_public_update(int id, int dst_id, int type, int src_port, const char* bind, const char* dst, uint16_t dst_port, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql),
        "UPDATE public SET `dst_id` = %d, `type` = %d, `port` = %d, `bind` = \"%s\", `dst` = \"%s\", `dst_port` = %d, `info` = \"%s\" WHERE id = %d",
        dst_id, type, src_port, bind, dst, dst_port, info ? info : "", id);
    //更新
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调

            return 0;
        }
    }
}
int data_public_del(uint32_t id) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM public WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调

            return 0;
        }
    }
    return -1;
}

cJSON* data_host_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM host;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_host_add(const char* host, int dst_id, int type, const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite, const char* info, uint8_t x_real_ip, uint8_t x_forwarded_for) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO host (`host`, `dst_id`, `type`, `bind`, `dst`, `dst_port`, `host_rewrite`, `info`, `x_real_ip`, `x_forwarded_for`)VALUES(\"%s\",%d, %d, \"%s\", \"%s\", %d, \"%s\", \"%s\",\"%d\",\"%d\");",
        host, dst_id, type, bind, dst, dst_port, host_rewrite ? host_rewrite : "", info ? info : "", x_real_ip, x_forwarded_for);
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            http_host_add(ops_get_http(global), id, host, dst_id, type, bind, dst, dst_port, host_rewrite, x_real_ip, x_forwarded_for);
            return 0;
        }
    }
    return -1;
}
int data_host_del(uint32_t id) {
    char* zErrMsg = 0;
    char sql[512] = { 0 };
    char host[256] = { 0 };
    snprintf(sql, sizeof(sql), "SELECT host FROM host WHERE id = %d;", id);
    cJSON* list = cJSON_CreateArray();
    if (sqlite3_exec(db, sql, _get_json_callback, list, &zErrMsg) == SQLITE_OK) {
        if (cJSON_GetArraySize(list) != 1) {
            cJSON_free(list);
            return -1;
        }
        cJSON* item = cJSON_GetArrayItem(list, 0);
        if (!item) {
            cJSON_free(list);
            return -1;
        }
        cJSON* h = cJSON_GetObjectItem(item, "host");
        if (!h || !h->valuestring) {
            cJSON_free(list);
            return -1;
        }
        strncpy(host, h->valuestring, 32);
    }
    cJSON_free(list);
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM host WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            http_host_del(ops_get_http(global), host);
            return 0;
        }
    }
    return -1;
}

cJSON* data_vpc_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM vpc;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_vpc_add(const char* ipv4, const char* ipv6, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO vpc (`ipv4`, `ipv6`, `info`)VALUES(\"%s\",\"%s\", \"%s\");",
        ipv4, ipv6, info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            ops_vpc_ctrl ctrl;
            ctrl.type = ops_vpc_ctrl_vpc_add;
            ctrl.vpc_add.id = id;
            ctrl.vpc_add.ipv4 = ipv4;
            ctrl.vpc_add.ipv6 = ipv6;
            bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
            return 0;
        }
    }
    return -1;
}
int data_vpc_del(uint16_t id) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM vpc WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_vpc_ctrl ctrl;
            ctrl.type = ops_vpc_ctrl_vpc_del;
            ctrl.vpc_del.id = id;
            bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
            return 0;
        }
    }
    return -1;
}

cJSON* data_member_get() {
    char* zErrMsg = 0;
    cJSON* list = cJSON_CreateArray();
    sqlite3_exec(db, "SELECT * FROM member;", _get_json_callback, list, &zErrMsg);
    return list;
}
int data_member_add(uint16_t bid, uint16_t vid, const char* ipv4, const char* ipv6, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO member (`bid`,`vid`,`ipv4`, `ipv6`, `info`)VALUES(%d, %d, \"%s\",\"%s\", \"%s\");",
        bid, vid, ipv4, ipv6, info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            ops_vpc_ctrl ctrl;
            ctrl.type = ops_vpc_ctrl_member_add;
            ctrl.member_add.id = id;
            ctrl.member_add.bid = bid;
            ctrl.member_add.vid = vid;
            ctrl.member_add.ipv4 = ipv4;
            ctrl.member_add.ipv6 = ipv6;
            bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
            return 0;
        }
    }
    return -1;
}
int data_member_del(uint32_t id) {
    char* zErrMsg = 0;
    char sql[256] = { 0 };
    //删除
    snprintf(sql, sizeof(sql), "DELETE FROM member WHERE id = %d;", id);
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        if (sqlite3_changes(db) == 1) {
            //触发回调
            ops_vpc_ctrl ctrl;
            ctrl.type = ops_vpc_ctrl_member_del;
            ctrl.member_del.id = id;
            bridge_mod_ctrl(manager, MODULE_VPC, &ctrl);
            return 0;
        }
    }
    return -1;
}