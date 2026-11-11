#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_273(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_blob *blob = NULL;
    int rc;
    const char *dbName = "main";
    const char *tableName = "test_table";
    const char *columnName = "test_column";
    sqlite_int64 rowId = 1;
    int flags = 0;

    // Ensure data is not NULL and has a valid size
    if (size < 1) {
        return 0;
    }

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a table and insert a row for testing
    const char *createTableSQL = "CREATE TABLE test_table (id INTEGER PRIMARY KEY, test_column BLOB);";
    const char *insertRowSQL = "INSERT INTO test_table (id, test_column) VALUES (1, x'00');";
    sqlite3_exec(db, createTableSQL, 0, 0, 0);
    sqlite3_exec(db, insertRowSQL, 0, 0, 0);

    // Attempt to open a blob
    rc = sqlite3_blob_open(db, dbName, tableName, columnName, rowId, flags, &blob);

    // Clean up
    if (blob) {
        sqlite3_blob_close(blob);
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

    LLVMFuzzerTestOneInput_273(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
