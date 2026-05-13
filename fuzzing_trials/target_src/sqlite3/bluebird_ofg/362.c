#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h> // Include for size_t
#include <stdlib.h> // Include for NULL
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_362(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_context *context;
    int rc;

    // Initialize SQLite in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a dummy function to obtain a context
    rc = sqlite3_create_function(db, "dummy_func", 0, SQLITE_UTF8, NULL, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a statement to execute the dummy function
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT dummy_func();", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement to get the context
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        context = (sqlite3_context *)sqlite3_column_value(stmt, 0);

        // Call the function-under-test
        void *user_data = sqlite3_user_data(context);

        // Use user_data in some way to avoid compiler optimizations
        if (user_data) {
            // Do something with user_data if needed
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

    LLVMFuzzerTestOneInput_362(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
