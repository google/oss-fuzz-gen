#include <sys/stat.h>
#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    // Initialize SQLite
    sqlite3_initialize();

    // Create an SQLite memory database
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    // Create an SQLite statement
    sqlite3_stmt *stmt;
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Insert data into the table
    sql = "INSERT INTO test (value) VALUES (?);";
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (size > 0) {
        sqlite3_bind_text(stmt, 1, (const char*)data, (int)size, SQLITE_STATIC);
    } else {
        sqlite3_bind_text(stmt, 1, "default", -1, SQLITE_STATIC);
    }
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Clean up
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

    LLVMFuzzerTestOneInput_265(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
