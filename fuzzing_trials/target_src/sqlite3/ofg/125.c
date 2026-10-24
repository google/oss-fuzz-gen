#include <stdint.h>
#include <stddef.h>  // Include this for size_t and NULL
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a statement
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement to ensure it's valid
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Reset the statement to reuse it
    sqlite3_reset(stmt);

    // Fuzzing the sqlite3_stmt_status function
    if (size >= 2) { // Ensure there is enough data to access data[0] and data[1]
        int op = data[0] % 2; // Limit the op to 0 or 1 for simplicity
        int resetFlag = data[1] % 2; // Limit resetFlag to 0 or 1
        int status = sqlite3_stmt_status(stmt, op, resetFlag);
    }

    // Finalize the statement and close the database
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

    LLVMFuzzerTestOneInput_125(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
