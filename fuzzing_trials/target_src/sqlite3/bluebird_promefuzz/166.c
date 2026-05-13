#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static void prepare_sqlite3_db(sqlite3 **db) {
    if (sqlite3_open(":memory:", db) != SQLITE_OK) {
        *db = NULL;
    }
}

static void finalize_and_close(sqlite3_stmt *stmt, sqlite3 *db) {
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    if (db) {
        sqlite3_close(db);
    }
}

int LLVMFuzzerTestOneInput_166(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = NULL;
    prepare_sqlite3_db(&db);
    if (!db) return 0;

    // Ensure the SQL statement is null-terminated
    char *zSql = (char *)malloc(Size + 1);
    if (!zSql) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(zSql, Data, Size);
    zSql[Size] = '\0';

    int nByte = (int)Size;

    sqlite3_stmt *stmt = NULL;
    const char *pzTail = NULL;

    // Fuzz sqlite3_prepare
    sqlite3_prepare(db, zSql, nByte, &stmt, &pzTail);
    finalize_and_close(stmt, db);

    prepare_sqlite3_db(&db);
    if (!db) {
        free(zSql);
        return 0;
    }

    stmt = NULL;
    pzTail = NULL;
    unsigned int prepFlags = 0;

    // Fuzz sqlite3_prepare_v3
    sqlite3_prepare_v3(db, zSql, nByte, prepFlags, &stmt, &pzTail);
    finalize_and_close(stmt, db);

    prepare_sqlite3_db(&db);
    if (!db) {
        free(zSql);
        return 0;
    }

    stmt = NULL;
    pzTail = NULL;

    // Fuzz sqlite3_prepare16_v2
    sqlite3_prepare16_v2(db, (const void *)zSql, nByte, &stmt, (const void **)&pzTail);
    finalize_and_close(stmt, db);

    prepare_sqlite3_db(&db);
    if (!db) {
        free(zSql);
        return 0;
    }

    stmt = NULL;
    pzTail = NULL;

    // Fuzz sqlite3_prepare16_v3
    sqlite3_prepare16_v3(db, (const void *)zSql, nByte, prepFlags, &stmt, (const void **)&pzTail);
    finalize_and_close(stmt, db);

    prepare_sqlite3_db(&db);
    if (!db) {
        free(zSql);
        return 0;
    }

    stmt = NULL;

    // Fuzz sqlite3_next_stmt
    stmt = sqlite3_next_stmt(db, NULL);
    finalize_and_close(stmt, db);

    prepare_sqlite3_db(&db);
    if (!db) {
        free(zSql);
        return 0;
    }

    stmt = NULL;
    pzTail = NULL;

    // Fuzz sqlite3_db_handle
    sqlite3_prepare_v2(db, zSql, nByte, &stmt, &pzTail);
    sqlite3 *dbHandle = sqlite3_db_handle(stmt);
    finalize_and_close(stmt, dbHandle);

    free(zSql);
    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_166(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
