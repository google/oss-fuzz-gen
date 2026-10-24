#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

// A helper function to create a simple SQLite statement for testing
sqlite3_stmt* create_test_stmt(sqlite3 *db) {
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT);"
                      "INSERT INTO test (id, name) VALUES (1, 'Alice');"
                      "SELECT id, name FROM test;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return NULL;
    }
    return stmt;
}

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    // Open an in-memory SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a test statement
    stmt = create_test_stmt(db);
    if (stmt == NULL) {
        sqlite3_close(db);
        return 0;
    }

    // Use the first byte of data as the index for sqlite3_column_decltype16
    int column_index = size > 0 ? data[0] % 2 : 0; // Since we have 2 columns

    // Call the function-under-test
    const void *decl_type = sqlite3_column_decltype16(stmt, column_index);

    // Normally, you would do something with decl_type, but for fuzzing, we just want to call it

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

    LLVMFuzzerTestOneInput_64(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
