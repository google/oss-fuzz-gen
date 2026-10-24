#include <stdint.h>
#include <stddef.h>  // Include this for size_t
#include <sqlite3.h>

// Function to be fuzzed
int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure that size is non-zero to avoid creating a NULL sqlite3_value
    if (size == 0) {
        return 0;
    }

    // Create a new SQLite database in memory
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy SQL statement
    sqlite3_stmt *stmt;
    const char *sql = "SELECT ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the input data to the SQL statement
    if (sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    sqlite3_step(stmt);

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

    LLVMFuzzerTestOneInput_32(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
