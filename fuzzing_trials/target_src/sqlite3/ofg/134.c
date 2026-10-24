#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sqlite3 *db;
    sqlite3_blob *blob = NULL;
    char *errMsg = 0;
    int rc;
    const char *dbName = "test.db";
    const char *tableName = "test_table";
    const char *columnName = "test_column";
    int rowId = 1;
    void *buffer;
    int bufferSize = size > 0 ? size : 1; // Use the size of the input data or minimum 1
    int offset = 0;

    // Open a connection to the database
    rc = sqlite3_open(dbName, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Create a table and clear it for testing
    const char *sqlCreateTable = "CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY, test_column BLOB)";
    rc = sqlite3_exec(db, sqlCreateTable, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Clear the table to ensure a fresh start for each test
    const char *sqlDelete = "DELETE FROM test_table";
    rc = sqlite3_exec(db, sqlDelete, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Only proceed if there's meaningful data to insert
    if (size > 0) {
        const char *sqlInsert = "INSERT INTO test_table (test_column) VALUES (?)";
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(db, sqlInsert, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_free(errMsg);
            sqlite3_close(db);
            return 0;
        }

        // Bind the input data to the statement
        rc = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        // Execute the statement
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        sqlite3_finalize(stmt);

        // Open the blob for reading
        rc = sqlite3_blob_open(db, "main", tableName, columnName, rowId, 0, &blob);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            return 0;
        }

        // Allocate buffer and copy data
        buffer = malloc(bufferSize);
        if (buffer == NULL) {
            sqlite3_blob_close(blob);
            sqlite3_close(db);
            return 0;
        }

        // Call the function-under-test
        rc = sqlite3_blob_read(blob, buffer, bufferSize, offset);
        if (rc != SQLITE_OK) {
            free(buffer);
            sqlite3_blob_close(blob);
            sqlite3_close(db);
            return 0;
        }

        // Process the buffer to ensure the data is being utilized
        // For example, print the first byte (if any) to simulate processing
        if (bufferSize > 0) {
            printf("First byte: %x\n", ((uint8_t*)buffer)[0]);
        }

        // New step: Execute a query that uses the inserted data
        const char *sqlSelect = "SELECT test_column FROM test_table WHERE id = ?";
        rc = sqlite3_prepare_v2(db, sqlSelect, -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, rowId);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const void *retrievedData = sqlite3_column_blob(stmt, 0);
                int retrievedSize = sqlite3_column_bytes(stmt, 0);
                if (retrievedData && retrievedSize > 0) {
                    printf("Retrieved first byte: %x\n", ((uint8_t*)retrievedData)[0]);
                }
            }
            sqlite3_finalize(stmt);
        }

        // Cleanup
        free(buffer);
        sqlite3_blob_close(blob);
    }

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

    LLVMFuzzerTestOneInput_134(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
