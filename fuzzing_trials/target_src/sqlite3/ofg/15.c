#include <stdint.h>
#include <stddef.h> // Include this for size_t
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a sqlite3_value object
    if (size == 0) {
        return 0;
    }

    // Initialize SQLite
    sqlite3_initialize();

    // Create a new SQLite database in memory
    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    // Create a prepared statement
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT ?;", -1, &stmt, NULL);

    // Bind the input data to the prepared statement
    sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT);

    // Step through the statement to evaluate it
    sqlite3_step(stmt);

    // Retrieve the value as text16
    const void *result = sqlite3_column_text16(stmt, 0);

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

    LLVMFuzzerTestOneInput_15(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
