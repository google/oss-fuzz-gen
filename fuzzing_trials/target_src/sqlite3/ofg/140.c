#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    int column_index = 0;  // Default column index to test

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a simple table and insert some data
    const char *create_table_sql = "CREATE TABLE test (id INTEGER, value TEXT);";
    rc = sqlite3_exec(db, create_table_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char *insert_data_sql = "INSERT INTO test (id, value) VALUES (1, 'Hello'), (2, 'World');";
    rc = sqlite3_exec(db, insert_data_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a simple query
    const char *query_sql = "SELECT * FROM test;";
    rc = sqlite3_prepare_v2(db, query_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement and iterate over rows
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Fuzz the column index using the input data
        if (size > 0) {
            column_index = data[0] % sqlite3_column_count(stmt);
        }

        // Call the function-under-test
        int bytes16 = sqlite3_column_bytes16(stmt, column_index);

        // Use bytes16 in some way to avoid compiler optimizations
        (void)bytes16;
    }

    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_140(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
