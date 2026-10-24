#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Function to prepare a dummy SQLite statement
static sqlite3_stmt* prepare_dummy_statement(sqlite3 *db) {
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, data BLOB);"
                      "INSERT INTO test (data) VALUES (x'00010203');"
                      "SELECT data FROM test WHERE id = 1;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return NULL;
    }
    return stmt;
}

int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy statement
    stmt = prepare_dummy_statement(db);
    if (stmt == NULL) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement to reach the result row
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Ensure index is within bounds
    int index = size > 0 ? data[0] % sqlite3_column_count(stmt) : 0;

    // Call the function-under-test
    const void *blob = sqlite3_column_blob(stmt, index);

    // Use the blob data if needed (for demonstration purposes, we'll just check if it's NULL)
    if (blob != NULL) {
        // Do something with the blob data
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_166(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
