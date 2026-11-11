#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>

// Define a custom destructor function
void custom_destructor_294(void *data) {
    // Free the allocated memory
    free(data);
}

int LLVMFuzzerTestOneInput_294(const uint8_t *data, size_t size) {
    // Initialize SQLite in-memory database and prepare a statement
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // Exit if database initialization fails
    }

    // Prepare a dummy SQL statement
    const char *sql = "SELECT ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // Exit if statement preparation fails
    }

    // Allocate memory for the blob data and copy the input data
    void *blob_data = malloc(size);
    if (blob_data == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0; // Exit if memory allocation fails
    }
    memcpy(blob_data, data, size);

    // Bind the blob data to the SQL statement
    sqlite3_bind_blob64(stmt, 1, blob_data, (sqlite3_uint64)size, custom_destructor_294);

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

    LLVMFuzzerTestOneInput_294(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
