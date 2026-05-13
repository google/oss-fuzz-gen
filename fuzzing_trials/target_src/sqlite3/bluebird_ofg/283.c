#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>  // Include for size_t and NULL
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_283(const uint8_t *data, size_t size) {
    // Initialize SQLite
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = "SELECT * FROM test WHERE id = ? AND name = ?";

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Use the fuzzing data as the index for the bind parameter
    int index = 0;
    if (size > 0) {
        index = data[0] % (sqlite3_bind_parameter_count(stmt) + 1); // Ensure index is within bounds
    }

    // Call the function-under-test
    const char *param_name = sqlite3_bind_parameter_name(stmt, index);

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

    LLVMFuzzerTestOneInput_283(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
