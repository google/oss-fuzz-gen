#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void dummyFunction(sqlite3_context *context, int argc, sqlite3_value **argv) {
    // Example function implementation for sqlite3_create_function
    sqlite3_result_null(context);
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db;
    sqlite3_blob *blob = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    char *errMsg = NULL;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table and blob
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);", NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_exec(db, "INSERT INTO test (data) VALUES (zeroblob(100));", NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Open a blob for writing
    rc = sqlite3_blob_open(db, "main", "test", "data", 1, 1, &blob);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Use a portion of the input data to write to the blob
    int writeSize = Size > 100 ? 100 : Size;
    rc = sqlite3_blob_write(blob, Data, writeSize, 0);
    sqlite3_errmsg(db); // Get error message

    // Close the blob
    sqlite3_blob_close(blob);

    // Open a blob for reading
    rc = sqlite3_blob_open(db, "main", "test", "data", 1, 0, &blob);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Read from the blob
    char buffer[100];
    rc = sqlite3_blob_read(blob, buffer, 100, 0);
    sqlite3_errmsg(db); // Get error message

    // Close the blob
    sqlite3_blob_close(blob);

    // Create a custom function
    rc = sqlite3_create_function(db, "dummy", 1, SQLITE_UTF8, NULL, dummyFunction, NULL, NULL);

    // Prepare a SQL statement
    const char *tail;
    rc = sqlite3_prepare_v2(db, "SELECT dummy(data) FROM test;", -1, &stmt, &tail);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt); // Execute the statement
        sqlite3_finalize(stmt); // Finalize the statement
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_57(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
