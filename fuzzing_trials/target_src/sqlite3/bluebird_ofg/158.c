#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Custom function to be used in SQL statement
static void custom_function(sqlite3_context *context, int argc, sqlite3_value **argv) {
    // Store some auxiliary data
    if (argc > 0) {
        const void *aux_data = sqlite3_value_blob(argv[0]);
        sqlite3_set_auxdata(context, 0, aux_data, NULL);
    }
}

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Initialize a dummy SQLite database and context
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, NULL);

    // Create a SQL function that uses custom_function
    sqlite3_create_function(db, "custom_function", 1, SQLITE_UTF8, NULL, custom_function, NULL, NULL);

    // Prepare a statement to use a valid context
    sqlite3_prepare_v2(db, "SELECT custom_function(value) FROM test WHERE id = ?;", -1, &stmt, NULL);

    // Bind an integer to the statement to ensure we have a valid context
    if (size >= sizeof(int)) {
        int idx = *((int *)data);
        sqlite3_bind_int(stmt, 1, idx);
    }

    // Step the statement to initialize the context
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Use a valid context from the custom function
        sqlite3_context *context = sqlite3_user_data(stmt);  // This line is not needed anymore

        // Call the function-under-test
        void *result = sqlite3_get_auxdata(context, 0);  // Correctly use the context from custom_function

        // Use the result in some way to avoid compiler optimizations removing the call
        if (result != NULL) {
            // Do something with result, e.g., print or log it
        }
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

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
