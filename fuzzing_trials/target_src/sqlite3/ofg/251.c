#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    // Ensure that the data size is large enough to be meaningful
    if (size < 1) return 0;

    // Initialize SQLite
    sqlite3_initialize();

    // Create an SQLite memory database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table to insert data
    const char *createTableSQL = "CREATE TABLE test (value BLOB);";
    sqlite3_exec(db, createTableSQL, 0, 0, 0);

    // Insert the fuzz data into the table
    sqlite3_stmt *stmt;
    const char *insertSQL = "INSERT INTO test (value) VALUES (?);";
    if (sqlite3_prepare_v2(db, insertSQL, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, data, (int)size, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Select the data back from the table
    const char *selectSQL = "SELECT value FROM test;";
    if (sqlite3_prepare_v2(db, selectSQL, -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            // Get the value as sqlite3_value
            const sqlite3_value *val = sqlite3_column_value(stmt, 0);

            // Call the function-under-test
            int type = sqlite3_value_type((sqlite3_value *)val);

            // Use the type for further processing or debugging
            (void)type; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_251(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
