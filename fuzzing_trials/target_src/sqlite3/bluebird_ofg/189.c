#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stddef.h>

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a meaningful sqlite3_value
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Initialize SQLite
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a simple table
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER);", 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare an SQL statement
    rc = sqlite3_prepare_v2(db, "INSERT INTO test (id) VALUES (?);", -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Set the value to an integer using the input data
    int64_t intValue = *(int64_t *)data;
    sqlite3_bind_int64(stmt, 1, intValue);

    // Execute the statement
    rc = sqlite3_step(stmt);

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Clean up
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

    LLVMFuzzerTestOneInput_189(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
