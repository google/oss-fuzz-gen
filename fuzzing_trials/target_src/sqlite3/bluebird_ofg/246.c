#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>
#include <stdlib.h>

// Dummy function to simulate a custom SQLite function that provides a context
static void dummy_sqlite_function(sqlite3_context *context, int argc, sqlite3_value **argv) {
    // Use the provided data as the error message
    const uint8_t *data = sqlite3_value_blob(argv[0]);
    int size = sqlite3_value_bytes(argv[0]);

    // Ensure the error message is null-terminated
    char *null_terminated_error_message = (char *)malloc(size + 1);
    if (null_terminated_error_message == NULL) {
        return;
    }
    memcpy(null_terminated_error_message, data, size);
    null_terminated_error_message[size] = '\0';

    // Use the size as the length of the error message
    int error_message_length = (int)size;

    // Call the function-under-test
    sqlite3_result_error(context, null_terminated_error_message, error_message_length);

    // Free allocated memory
    free(null_terminated_error_message);
}

// Fuzzing harness for sqlite3_result_error
int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create an in-memory database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Register the dummy function
    sqlite3_create_function(db, "dummy_func", 1, SQLITE_UTF8, NULL, dummy_sqlite_function, NULL, NULL);

    // Prepare a statement to invoke the function
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT dummy_func(?);", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the data to the statement
    sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC);

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

    LLVMFuzzerTestOneInput_246(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
