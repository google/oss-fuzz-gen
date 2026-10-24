#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_379(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if(rc) {
        sqlite3_close(db);
        return 0;
    }

    // Convert the fuzz input into a null-terminated string
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the SQL command
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free allocated resources
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_free
    sqlite3_free((void *)errMsg);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    free(sql);
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

    LLVMFuzzerTestOneInput_379(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
