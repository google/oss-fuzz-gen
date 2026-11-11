#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

// A dummy destructor function to satisfy the sqlite3_bind_blob64 signature
void dummy_destructor_238(void* data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy SQL statement
    const char *sql_create = "CREATE TABLE test (id INTEGER PRIMARY KEY, value BLOB);";
    rc = sqlite3_exec(db, sql_create, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare an SQL statement for inserting data
    const char *sql_insert = "INSERT INTO test (value) VALUES (?);";
    rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the data as a blob to the first parameter index
    int index = 1; // Typically, parameter indices start from 1 in SQLite
    sqlite3_uint64 blob_size = (sqlite3_uint64)size;
    rc = sqlite3_bind_blob64(stmt, index, (const void *)data, blob_size, dummy_destructor_238);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
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

    LLVMFuzzerTestOneInput_238(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
