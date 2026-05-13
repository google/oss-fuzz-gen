#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

// Define a helper function to initialize a sqlite3_value from raw data
sqlite3_value* create_sqlite3_value_from_data(const uint8_t *data, size_t size) {
    sqlite3_value *value = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    // Open an in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return NULL;
    }

    // Prepare a dummy statement to get a sqlite3_value
    if (sqlite3_prepare_v2(db, "SELECT ?", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    // Bind the data as a blob to the statement
    if (sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return NULL;
    }

    // Step the statement to initialize the value
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Instead of directly using sqlite3_column_value, we copy the value to prevent use-after-free
        const void *blob = sqlite3_column_blob(stmt, 0);
        int bytes = sqlite3_column_bytes(stmt, 0);
        if (blob && bytes > 0) {
            // Create a new sqlite3_value and copy the blob data into it
            value = sqlite3_value_dup(sqlite3_column_value(stmt, 0));
        }
    }

    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return value;
}

int LLVMFuzzerTestOneInput_299(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to initialize a sqlite3_value
    if (size == 0) {
        return 0;
    }

    // Open an in-memory database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a table
    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS fuzz_table (id INTEGER PRIMARY KEY, data BLOB);";
    if (sqlite3_exec(db, create_table_sql, 0, 0, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Insert the fuzz data into the table
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO fuzz_table (data) VALUES (?);", -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Query the data back
    if (sqlite3_prepare_v2(db, "SELECT data FROM fuzz_table WHERE id = 1;", -1, &stmt, 0) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            // Retrieve the blob to ensure the query executed
            const void *result_blob = sqlite3_column_blob(stmt, 0);
            int result_bytes = sqlite3_column_bytes(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Close the database
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

    LLVMFuzzerTestOneInput_299(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
