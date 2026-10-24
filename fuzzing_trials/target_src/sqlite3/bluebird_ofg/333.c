#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Custom SQLite function to call sqlite3_result_int64
static void custom_function(sqlite3_context *context, int argc, sqlite3_value **argv) {
    if (argc == 1) {
        sqlite3_int64 value = sqlite3_value_int64(argv[0]);
        sqlite3_result_int64(context, value);
    }
}

// Fuzzing harness for sqlite3_result_int64
int LLVMFuzzerTestOneInput_333(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sqlite3_int64 value;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Ensure size is sufficient to extract a sqlite3_int64 value
    if (size < sizeof(sqlite3_int64)) {
        return 0;
    }

    // Extract a sqlite3_int64 value from the input data
    value = *((sqlite3_int64 *)data);

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Register the custom function
    rc = sqlite3_create_function(db, "custom_function", 1, SQLITE_UTF8, NULL, custom_function, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a SQL statement to invoke the custom function
    rc = sqlite3_prepare_v2(db, "SELECT custom_function(?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the extracted value to the SQL statement
    rc = sqlite3_bind_int64(stmt, 1, value);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
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

    LLVMFuzzerTestOneInput_333(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
