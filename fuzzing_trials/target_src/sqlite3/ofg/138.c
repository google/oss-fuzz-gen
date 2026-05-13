#include <stdint.h>
#include <stddef.h>
#include "/src/sqlite3/bld/sqlite3.h"

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *next_stmt = NULL;

    // Ensure we have some data to work with
    if (size < 1) {
        return 0;
    }

    // Open an in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Attempt to prepare a statement if data is available
    if (size > 1) {
        const char *sql = (const char *)data;
        sqlite3_prepare_v2(db, sql, size, &stmt, NULL);
    }

    // Call the function-under-test
    next_stmt = sqlite3_next_stmt(db, stmt);

    // Clean up
    if (stmt) {
        sqlite3_finalize(stmt);
    }
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

    LLVMFuzzerTestOneInput_138(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
