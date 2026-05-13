#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_blob *blob;
    int rc;
    void *buffer;
    int buffer_size;
    int offset;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a table and insert a blob for testing
    const char *create_table_sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);";
    const char *insert_blob_sql = "INSERT INTO test (data) VALUES (zeroblob(100));";

    rc = sqlite3_exec(db, create_table_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_exec(db, insert_blob_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Open a blob for reading
    rc = sqlite3_blob_open(db, "main", "test", "data", 1, 0, &blob);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare buffer and offset for reading
    buffer_size = size > 100 ? 100 : (int)size; // Limit to 100 bytes
    buffer = malloc(buffer_size);
    if (buffer == NULL) {
        sqlite3_blob_close(blob);
        sqlite3_close(db);
        return 0;
    }

    offset = 0; // Start reading from the beginning of the blob

    // Call the function-under-test
    rc = sqlite3_blob_read(blob, buffer, buffer_size, offset);
    if (rc != SQLITE_OK) {
        // Handle read error
        free(buffer);
        sqlite3_blob_close(blob);
        sqlite3_close(db);
        return 0;
    }

    // Clean up
    free(buffer);
    sqlite3_blob_close(blob);
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

    LLVMFuzzerTestOneInput_105(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
