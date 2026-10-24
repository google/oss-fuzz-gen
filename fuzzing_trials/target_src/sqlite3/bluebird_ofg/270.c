#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Check if the input size is zero; if so, return immediately
    if (size == 0 || data == NULL) {
        return 0;
    }

    // Ensure null-termination of the data to prevent buffer overflows
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Create a SQLite memory database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        free(null_terminated_data);
        return 0; // Unable to open database
    }

    // Prepare a statement to test
    sqlite3_stmt *stmt;
    const char *sql = "SELECT ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(null_terminated_data);
        return 0; // Unable to prepare statement
    }

    // Bind the data provided by the fuzzer to the statement
    // Use SQLITE_STATIC instead of SQLITE_TRANSIENT to avoid potential issues with memory management
    if (sqlite3_bind_text(stmt, 1, null_terminated_data, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(null_terminated_data);
        return 0; // Unable to bind data
    }

    // Execute the statement
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Access the result if needed
        const unsigned char *result = sqlite3_column_text(stmt, 0);
        (void)result; // Suppress unused variable warning
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_270(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
