#include "data.h"
#include <sqlite3.h>

static sqlite3* db = NULL;

static int callback(void* NotUsed, int argc, char** argv, char** azColName) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int data_init(const char* file) {
    sqlite3_initialize();
    int ret = sqlite3_open_v2(file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    //³õÊ¼»¯
    char* zErrMsg = 0;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS bridge (id INTEGER PRIMARY KEY AUTOINCREMENT, key VARCHAR(64) NOT NULL); ", callback, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE UNIQUE INDEX key ON bridge (key);", callback, 0, &zErrMsg);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS forward (id INTEGER PRIMARY KEY AUTOINCREMENT,src_id INTEGER NOT NULL, dst_id INTEGER NOT NULL,type INTEGER NOT NULL, src_port INTEGER NOT NULL,dst TEXT NOT NULL, dst_port INTEGER NOT NULL); ", callback, 0, &zErrMsg);

}

uint16_t data_find_auth_key(const char* key, int key_len) {
    if (key[0] == 'a') {
        return 1;
    }
    if (key[0] == 'b') {
        return 2;
    }
    return 1;
}
