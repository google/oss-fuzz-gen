#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_blob *blob;
    int rc;
    const char *db_name = "test.db";
    const char *table_name = "test_table";
    const char *column_name = "test_column";
    int row_id = 1;
    int blob_size = 1024; // Arbitrary blob size for testing

    if (size == 0) {
        return 0;
    }

    // Open a database connection
    rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a table with a BLOB column if it doesn't exist
    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY, test_column BLOB)";
    rc = sqlite3_exec(db, create_table_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Insert a row if it doesn't exist
    const char *insert_sql = "INSERT OR IGNORE INTO test_table (id, test_column) VALUES (1, zeroblob(1024))";
    rc = sqlite3_exec(db, insert_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Open the blob for writing
    rc = sqlite3_blob_open(db, "main", table_name, column_name, row_id, 1, &blob);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Determine the number of bytes to write
    int bytes_to_write = (size < blob_size) ? size : blob_size;

    // Call the function-under-test
    sqlite3_blob_write(blob, data, bytes_to_write, 0);

    // Close the blob handle
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

    LLVMFuzzerTestOneInput_197(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
