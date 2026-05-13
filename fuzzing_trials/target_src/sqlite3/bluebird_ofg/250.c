#include <sys/stat.h>
#include <string.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_250(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *next_stmt = NULL;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a simple SQL statement if size is non-zero
    if (size > 0) {
        rc = sqlite3_prepare_v2(db, (const char *)data, size, &stmt, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            return 0;
        }
    }

    // Call the function-under-test
    next_stmt = sqlite3_next_stmt(db, stmt);

    // Finalize the statement if it was prepared
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    // Close the database connection
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

    LLVMFuzzerTestOneInput_250(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
