#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void setupDatabase(sqlite3 **db, sqlite3_stmt **stmt) {
    int rc = sqlite3_open(":memory:", db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return;
    }

    char *errMsg = 0;
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);"
                      "INSERT INTO test (data) VALUES (x'12345678');";
    rc = sqlite3_exec(*db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(*db);
        return;
    }

    const char *stmtSQL = "SELECT data FROM test;";
    rc = sqlite3_prepare_v2(*db, stmtSQL, -1, stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(*db));
        sqlite3_close(*db);
    }
}

int LLVMFuzzerTestOneInput_175(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    setupDatabase(&db, &stmt);

    if (db == NULL || stmt == NULL) {
        return 0;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "Failed to step: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    int iCol = 0;
    if (Size > 0) {
        iCol = Data[0] % sqlite3_column_count(stmt);
    }

    sqlite3_column_bytes(stmt, iCol);
    sqlite3_column_blob(stmt, iCol);
    sqlite3_column_bytes(stmt, iCol);
    sqlite3_column_blob(stmt, iCol);

    sqlite3_stmt_isexplain(stmt);
    sqlite3_reset(stmt);
    sqlite3_step(stmt);

    sqlite3_errmsg(db);
    sqlite3_errmsg(db);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

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

    LLVMFuzzerTestOneInput_175(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
