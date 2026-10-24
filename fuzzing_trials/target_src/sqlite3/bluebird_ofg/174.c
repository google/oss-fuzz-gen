#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;
    char *sql = NULL;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Create a simple table
    sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);";
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Use the input data to manipulate the database
    if (size > 0) {
        // Ensure the input data is null-terminated before using it in sqlite3_mprintf
        char *inputStr = (char *)malloc(size + 1);
        if (!inputStr) {
            sqlite3_close(db);
            return 0;
        }
        memcpy(inputStr, data, size);
        inputStr[size] = '\0';

        // Prepare an SQL statement using the input data
        sql = sqlite3_mprintf("INSERT INTO test (value) VALUES (%Q);", inputStr);
        free(inputStr);
        rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        sqlite3_free(sql);
        if (rc != SQLITE_OK) {
            sqlite3_free(errMsg);
            sqlite3_close(db);
            return 0;
        }
    }

    // Call the function-under-test
    sqlite3_int64 changes = sqlite3_changes64(db);

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

    LLVMFuzzerTestOneInput_174(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
