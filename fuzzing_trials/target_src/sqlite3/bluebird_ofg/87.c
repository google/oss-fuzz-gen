#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Initialize SQLite (required before using any SQLite functions)
    if (sqlite3_initialize() != SQLITE_OK) {
        return 0;
    }

    // Open an in-memory SQLite database
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open((const char *)"r", &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Ensure the input data is null-terminated
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Attempt to execute the input data as SQL
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 4 of sqlite3_exec
    rc = sqlite3_exec(db, sql, 0, 0, NULL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
    }

    // Free the allocated memory for SQL
    free(sql);

    // Close the database
    sqlite3_close(db);

    // Shutdown SQLite
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

    LLVMFuzzerTestOneInput_87(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
