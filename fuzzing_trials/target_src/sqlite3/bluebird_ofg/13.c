#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Initialize SQLite
    sqlite3_initialize();

    // Open an in-memory SQLite database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Create a new SQL statement from the input data
    char *sql = sqlite3_mprintf("%.*s", (int)size, data);

    // Execute the SQL statement
    char *errMsg = NULL;
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Clean up
    if (errMsg) {
        sqlite3_free(errMsg);
    }
    sqlite3_free(sql);
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

    LLVMFuzzerTestOneInput_13(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
