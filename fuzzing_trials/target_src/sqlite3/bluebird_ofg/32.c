#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;

    // Initialize a SQLite database in memory
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // If opening the database fails, return
    }

    // Ensure the input data is null-terminated
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        sqlite3_close(db);
        return 0; // If memory allocation fails, return
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Use the input data as an SQL statement
    if (size > 0) {
        sqlite3_exec(db, sql, 0, 0, &errMsg);
    }

    // Reset auto extension (function under test)
    sqlite3_reset_auto_extension();

    // Clean up
    sqlite3_close(db);
    if (errMsg) {
        sqlite3_free(errMsg);
    }
    free(sql);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_32(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
