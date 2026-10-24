#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_blob *blob = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    char *errMsg = NULL;
    const char *dbName = "fuzz_db";
    const char *tableName = "fuzz_table";
    const char *columnName = "fuzz_column";
    const char *createTableSQL = "CREATE TABLE IF NOT EXISTS fuzz_table (id INTEGER PRIMARY KEY, fuzz_column BLOB);";
    const char *insertSQL = "INSERT INTO fuzz_table (fuzz_column) VALUES (?);";

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    // Create a table
    rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    // Insert fuzz data into the table
    rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    rc = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        goto cleanup;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    // Open a blob handle
    rc = sqlite3_blob_open(db, dbName, tableName, columnName, 1, 0, &blob);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    // Call the function-under-test
    int blobSize = sqlite3_blob_bytes(blob);

    // Use the blobSize in some way to avoid compiler optimizations
    if (blobSize > 0) {
        // Do something with blobSize, e.g., print or store it
    }

cleanup:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    if (blob != NULL) {
        sqlite3_blob_close(blob);
    }
    if (db != NULL) {
        sqlite3_close(db);
    }
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

    LLVMFuzzerTestOneInput_139(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
