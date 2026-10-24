#include <stdint.h>
#include <stddef.h>  // Include this for size_t and NULL
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_value *value;
    int rc;

    // Initialize SQLite
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Prepare a simple SQL statement
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value BLOB);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }

    // Execute the statement to create the table
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Prepare an insert statement
    sql = "INSERT INTO test (value) VALUES (?);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }

    // Bind the input data directly to the statement
    rc = sqlite3_bind_blob(stmt, 1, data, (int)size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }

    // Execute the insert statement
    rc = sqlite3_step(stmt);

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_247(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
