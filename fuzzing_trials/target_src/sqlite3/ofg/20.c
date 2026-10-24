#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sqlite3 *db = NULL;
    sqlite3_blob *blob = NULL;
    sqlite3_int64 rowid = 1; // Initialize rowid with a non-zero value

    // Open an in-memory SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a table and insert a row to have a blob to work with
    const char *createTableSQL = "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);";
    const char *insertSQL = "INSERT INTO test (data) VALUES (zeroblob(10));";

    if (sqlite3_exec(db, createTableSQL, 0, 0, 0) != SQLITE_OK ||
        sqlite3_exec(db, insertSQL, 0, 0, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Open a blob for the inserted row
    if (sqlite3_blob_open(db, "main", "test", "data", rowid, 1, &blob) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Use the fuzz data to set a new rowid
    if (size >= sizeof(sqlite3_int64)) {
        rowid = *(const sqlite3_int64 *)data;
    }

    // Call the function-under-test
    sqlite3_blob_reopen(blob, rowid);

    // Cleanup
    sqlite3_blob_close(blob);
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

    LLVMFuzzerTestOneInput_20(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
