#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_blob *blob = NULL;
    const char *db_name = "main"; // Use "main" for in-memory database
    const char *table_name = "test_table";
    const char *column_name = "test_column";
    sqlite_int64 rowid = 1;
    int flags = 0;

    // Initialize SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a table for testing
    char *err_msg = NULL;
    const char *create_table_sql = "CREATE TABLE test_table (id INTEGER PRIMARY KEY, test_column BLOB);";
    if (sqlite3_exec(db, create_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 0;
    }

    // Insert a row for testing
    const char *insert_sql = "INSERT INTO test_table (test_column) VALUES (zeroblob(10));";
    if (sqlite3_exec(db, insert_sql, 0, 0, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 0;
    }

    // Call the function-under-test
    int result = sqlite3_blob_open(db, db_name, table_name, column_name, rowid, flags, &blob);

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

    LLVMFuzzerTestOneInput_99(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
