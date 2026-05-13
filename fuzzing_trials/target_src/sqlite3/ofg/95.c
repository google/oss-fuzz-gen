#include <stddef.h>  // Include for size_t
#include <stdint.h>
#include <sqlite3.h>
#include <string.h>   // Include for memcpy

// Define a dummy callback function to use with sqlite3_commit_hook
static int dummy_callback(void *data) {
    return 0; // Return 0 to indicate success
}

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = NULL;
    void *hook_data = (void *)data; // Use the input data as hook data

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Set the commit hook
    sqlite3_commit_hook(db, dummy_callback, hook_data);

    // Create a table and insert data to trigger the commit hook
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Prepare an SQL statement using the fuzz input data
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO test (value) VALUES (?);", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        // Bind the fuzz input data to the SQL statement
        sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT);
        
        // Execute the SQL statement
        sqlite3_step(stmt);
        
        // Finalize the statement
        sqlite3_finalize(stmt);
    }

    // Close the database
    sqlite3_close(db);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_95(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
