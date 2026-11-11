#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_248(const uint8_t *data, size_t size) {
    // Initialize SQLite database and statement
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a simple SQL statement
    const char *sql = "CREATE TABLE test (id INTEGER, value TEXT); INSERT INTO test (id, value) VALUES (?, ?);";
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER, value TEXT);", 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_prepare_v2(db, "INSERT INTO test (id, value) VALUES (?, ?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the input data to the SQL statement
    if (size > 0) {
        // Bind the first byte of data as the id
        rc = sqlite3_bind_int(stmt, 1, data[0]);
        if (rc != SQLITE_OK) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        // Bind the rest of the data as the value
        rc = sqlite3_bind_text(stmt, 2, (const char *)(data + 1), size - 1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        // Execute the SQL statement
        rc = sqlite3_step(stmt);
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

    LLVMFuzzerTestOneInput_248(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
