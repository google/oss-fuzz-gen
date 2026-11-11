#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    if (size < sizeof(sqlite3_uint64) + sizeof(int)) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a simple table
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB)";
    rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare an insert statement
    const char *insert_sql = "INSERT INTO test (data) VALUES (?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Extract the integer and sqlite3_uint64 values from the input data
    int index = *(int *)data;
    sqlite3_uint64 size64;
    memcpy(&size64, data + sizeof(int), sizeof(sqlite3_uint64));

    // Bind a zero blob to the prepared statement
    sqlite3_bind_zeroblob64(stmt, index, size64);

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

    LLVMFuzzerTestOneInput_239(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
