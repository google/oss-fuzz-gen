#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Define a custom destructor function for demonstration purposes
void custom_destructor_491(void *ptr) {
    // Custom cleanup logic if needed
}

// A custom SQL function to provide a valid sqlite3_context
static void custom_sql_function(sqlite3_context *context, int argc, sqlite3_value **argv) {
    const char *text = (const char *)sqlite3_value_text(argv[0]);
    sqlite3_uint64 text_length = sqlite3_value_bytes(argv[0]);
    unsigned char encoding = SQLITE_UTF8;

    // Call the function-under-test
    sqlite3_result_text64(context, text, text_length, custom_destructor_491, encoding);
}

int LLVMFuzzerTestOneInput_491(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, return immediately
    }

    // Register the custom SQL function
    rc = sqlite3_create_function(db, "custom_function", 1, SQLITE_UTF8, NULL, custom_sql_function, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // If registering the function fails, return immediately
    }

    // Prepare a SQL statement that uses the custom function
    rc = sqlite3_prepare_v2(db, "SELECT custom_function(?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // If preparing the statement fails, return immediately
    }

    // Bind the fuzzer data to the SQL statement
    rc = sqlite3_bind_text(stmt, 1, (const char *)data, (int)size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0; // If binding the data fails, return immediately
    }

    // Execute the statement
    rc = sqlite3_step(stmt);

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

    LLVMFuzzerTestOneInput_491(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
