#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_204(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        return 0;
    }

    // Ensure data is null-terminated and non-empty for use as a table name
    char tableName[256];
    size_t tableNameSize = size < 255 ? size : 255;
    memcpy(tableName, data, tableNameSize);
    tableName[tableNameSize] = '\0';

    // Create a simple table
    char createTableSQL[512];
    snprintf(createTableSQL, sizeof(createTableSQL), "CREATE TABLE %s (id INT);", tableName);
    rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Call the function-under-test
    sqlite3_db_readonly(db, tableName);

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

    LLVMFuzzerTestOneInput_204(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
