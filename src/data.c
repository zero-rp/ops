#include <stdio.h>

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
    settings->on_forward_add(userdata, atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5], atoi(argv[6]));
    return 0;
}
static int _host_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    settings->on_host_add(userdata, atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], atoi(argv[5]));
    return 0;
}
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
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS bridge (id INTEGER PRIMARY KEY AUTOINCREMENT, key VARCHAR(64) NOT NULL); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX key ON bridge (key);", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS forward (id INTEGER PRIMARY KEY AUTOINCREMENT,src_id INTEGER NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, src_port INTEGER NOT NULL,dst TEXT NOT NULL, dst_port INTEGER NOT NULL); ", NULL, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS host (id INTEGER PRIMARY KEY AUTOINCREMENT, host VARCHAR(256) NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, dst TEXT NOT NULL, dst_port INTEGER NOT NULL); ", NULL, 0, &zErrMsg);

    //加载数据
    sqlite3_exec(db, "SELECT id, key FROM bridge;", _key_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM forward;", _forward_callback, NULL, &zErrMsg);
    sqlite3_exec(db, "SELECT * FROM host;", _host_callback, NULL, &zErrMsg);

    return 0;
}


//添加数据


