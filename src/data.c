﻿#include <stdio.h>

#include "data.h"
#include <sqlite3.h>

static sqlite3* db = NULL;
static struct data_settings* settings = NULL;
static void* userdata = NULL;

static int _key_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_key_add(userdata, atoi(argv[0]), argv[1]);
    return 0;
}
static int _forward_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_forward_add(userdata, atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5], argv[6], atoi(argv[7]));
    return 0;
}
static int _host_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_host_add(userdata, atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], atoi(argv[6]), argv[7]);
    return 0;
}
static int _vpc_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_vpc_add(userdata, atoi(argv[0]), argv[1], argv[2]);
    return 0;
}
static int _member_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_member_add(userdata, atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), argv[3], argv[4]);
    return 0;
}
//初始化
int data_init(const char* file, void* ud, struct data_settings* set) {
    sqlite3_initialize();
    int ret = sqlite3_open_v2(file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    userdata = ud;
    settings = set;
    //初始化
    char* zErrMsg = 0;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS bridge (id INTEGER PRIMARY KEY AUTOINCREMENT, key VARCHAR(64) NOT NULL, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX key ON bridge (key);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS forward (id INTEGER PRIMARY KEY AUTOINCREMENT,src_id INTEGER NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, src_port INTEGER NOT NULL,bind TEXT, dst TEXT NOT NULL, dst_port INTEGER NOT NULL, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS host (id INTEGER PRIMARY KEY AUTOINCREMENT, host VARCHAR(256) NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, bind TEXT, dst TEXT NOT NULL, dst_port INTEGER NOT NULL, host_rewrite TEXT, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS vpc (id INTEGER PRIMARY KEY AUTOINCREMENT, ipv4 TEXT, ipv6 TEXT, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX vipv4 ON vpc (ipv4);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX vipv6 ON vpc (ipv6);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS member (id INTEGER PRIMARY KEY AUTOINCREMENT, bid INTEGER NOT NULL, vid INTEGER NOT NULL, ipv4 TEXT, ipv6 TEXT, info TEXT); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX mipv4 ON member (ipv4);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX mipv6 ON member (ipv6);", NULL, 0, &zErrMsg);

    //加载数据
    sqlite3_exec(db, "SELECT id, key FROM bridge;", _key_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM forward;", _forward_callback, NULL, &zErrMsg);
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
            settings->on_key_add(userdata, id, key);
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
            settings->on_key_del(userdata, key);
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
            settings->on_key_new(userdata, id, key);
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
            settings->on_forward_add(userdata, id, src_id, dst_id, type, src_port, bind, dst, dst_port);
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
            settings->on_forward_update(userdata, id, src_id, dst_id, type, src_port, bind, dst, dst_port);
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
            settings->on_forward_del(userdata, id);
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
int data_host_add(const char* host, int dst_id, int type, const char* bind, const char* dst, uint16_t dst_port, const char* host_rewrite, const char* info) {
    char sql[1024] = { 0 };
    snprintf(sql, sizeof(sql), "INSERT INTO host (`host`, `dst_id`, `type`, `bind`, `dst`, `dst_port`, `host_rewrite`, `info`)VALUES(\"%s\",%d, %d, \"%s\", \"%s\", %d, \"%s\", \"%s\");",
        host, dst_id, type, bind, dst, dst_port, host_rewrite ? host_rewrite : "", info ? info : "");
    char* zErrMsg = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &zErrMsg) == SQLITE_OK) {
        //查询
        uint32_t id = sqlite3_last_insert_rowid(db);
        if (id > 0) {
            //触发回调
            settings->on_host_add(userdata, id, host, dst_id, type, bind, dst, dst_port, host_rewrite);
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
            settings->on_host_del(userdata, host);
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
            settings->on_vpc_add(userdata, id, ipv4, ipv6);
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
            settings->on_vpc_del(userdata, id);
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
            settings->on_member_add(userdata, id, bid, vid, ipv4, ipv6);
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
            settings->on_member_del(userdata, id);
            return 0;
        }
    }
    return -1;
}