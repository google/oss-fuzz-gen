#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Initialize SQLite3 value
    sqlite3_value *value;
    sqlite3_value *values[1];
    sqlite3 *db;
    sqlite3_stmt *stmt;

    // Open a temporary SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, blobdata BLOB);";
    if (sqlite3_exec(db, sql, 0, 0, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare an insert statement
    sql = "INSERT INTO test (blobdata) VALUES (?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the fuzz data as a blob
    if (sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Reset the statement
    sqlite3_reset(stmt);

    // Prepare a select statement to retrieve the blob
    sql = "SELECT blobdata FROM test WHERE id = 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Get the blob value
        value = (sqlite3_value *)sqlite3_column_value(stmt, 0);

        // Call the function-under-test
        const void *blob = sqlite3_value_blob(value);

        // Use the blob (in this case, just to avoid compiler warnings)
        if (blob != NULL) {
            volatile unsigned char dummy = *((unsigned char *)blob);
            (void)dummy;
        }
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

    LLVMFuzzerTestOneInput_116(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
