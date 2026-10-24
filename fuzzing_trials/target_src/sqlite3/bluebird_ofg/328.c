#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

// Define a callback function that matches the expected signature for the busy handler
int busy_handler_callback(void *ptr, int count) {
    // Example logic for the busy handler
    return 0; // Return 0 to indicate that the busy handler should not retry
}

int LLVMFuzzerTestOneInput_328(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    char *errMsg = NULL;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Use the provided fuzz data as a pointer to pass to the busy handler
    void *ptr = (void *)data;

    // Call the function-under-test with the database, callback, and pointer
    sqlite3_busy_handler(db, busy_handler_callback, ptr);

    // Create a table to perform operations on
    rc = sqlite3_exec(db, "CREATE TABLE test(id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Ensure the fuzz data is null-terminated before using it in sqlite3_mprintf
    char *safe_data = strndup((const char *)data, size);
    if (!safe_data) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare an SQL statement using the fuzz data
    char *sql = sqlite3_mprintf("INSERT INTO test(value) VALUES(%Q);", safe_data);
    free(safe_data); // Free the duplicated string
    if (sql) {
        // Execute the SQL statement
        rc = sqlite3_exec(db, sql, NULL, NULL, &errMsg);
        sqlite3_free(sql);
    }

    if (errMsg) {
        sqlite3_free(errMsg);
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

    LLVMFuzzerTestOneInput_328(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
