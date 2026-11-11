#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Prepare a simple SQL statement
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt != NULL) {
        // Bind the input data to the statement (if possible)
        if (size > 0) {
            sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT);
        }

        // Call the function-under-test
        sqlite3_clear_bindings(stmt);

        // Finalize the statement
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

    LLVMFuzzerTestOneInput_202(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
