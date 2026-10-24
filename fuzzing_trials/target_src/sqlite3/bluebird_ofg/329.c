#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include <stdlib.h>  // Include for NULL
#include "sqlite3.h"
#include <string.h>  // Include for memcpy

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = NULL;
    int rc;

    // Initialize SQLite library
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function sqlite3_initialize with sqlite3_global_recover
    if (sqlite3_global_recover() != SQLITE_OK) {
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
        return 0;
    }

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Create a null-terminated string from the input data
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the input data as an SQL statement
    rc = sqlite3_exec(db, sql, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK && errMsg != NULL) {
        sqlite3_free(errMsg);
    }

    // Clean up
    free(sql);
    sqlite3_close(db);
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_329(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
