#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h> // Include for size_t
#include <stdlib.h> // Include for NULL
#include "sqlite3.h"
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_360(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Ensure that the database is not NULL
    if (db != NULL) {
        // Create a table to ensure some database activity
        const char *createTableSQL = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";
        rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            sqlite3_free(errMsg);
            sqlite3_close(db);
            return 0;
        }

        // Insert data into the table using fuzz input
        if (size > 0) {
            // Create a null-terminated copy of the data
            char *dataCopy = (char *)malloc(size + 1);
            if (dataCopy == NULL) {
                sqlite3_close(db);
                return 0;
            }
            memcpy(dataCopy, data, size);
            dataCopy[size] = '\0';

            char *insertSQL = sqlite3_mprintf("INSERT INTO test (value) VALUES (%Q);", dataCopy);
            free(dataCopy); // Free the allocated memory for dataCopy
            rc = sqlite3_exec(db, insertSQL, 0, 0, &errMsg);
            sqlite3_free(insertSQL);
            if (rc != SQLITE_OK) {
                sqlite3_free(errMsg);
                sqlite3_close(db);
                return 0;
            }
        }

        // Call the function-under-test
        int autocommit = sqlite3_get_autocommit(db);
        
        // Use the result in some way to avoid compiler optimizations
        if (autocommit) {
            // Do something if autocommit is enabled
        } else {
            // Do something if autocommit is disabled
        }
    }

    // Close the database connection
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

    LLVMFuzzerTestOneInput_360(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
