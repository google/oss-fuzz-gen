#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_blob *blob = NULL;
    int rc;
    const char *table_name = "test_table";
    const char *column_name = "test_column";
    int row_id = 1;

    // Initialize SQLite in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a table and insert a blob
    const char *sql_create_table = "CREATE TABLE test_table (id INTEGER PRIMARY KEY, test_column BLOB)";
    rc = sqlite3_exec(db, sql_create_table, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char *sql_insert_blob = "INSERT INTO test_table (id, test_column) VALUES (1, zeroblob(10))";
    rc = sqlite3_exec(db, sql_insert_blob, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Open the blob
    rc = sqlite3_blob_open(db, "main", table_name, column_name, row_id, 0, &blob);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Modify the blob using the input data
    size_t write_size = size < 10 ? size : 10; // Ensure we don't exceed the blob size
    rc = sqlite3_blob_write(blob, data, write_size, 0);
    if (rc != SQLITE_OK) {
        sqlite3_blob_close(blob);
        sqlite3_close(db);
        return 0;
    }

    // Call the function-under-test
    sqlite3_blob_close(blob);

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

    LLVMFuzzerTestOneInput_135(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
