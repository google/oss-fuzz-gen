#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;

    // Open a new in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Execute a simple SQL statement to ensure the database is initialized
    char *errMsg = 0;
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);", 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0; // If table creation fails, exit early
    }

    // Use the input data to execute SQL statements
    if (size > 0) {
        char *sql = (char *)malloc(size + 1);
        if (sql) {
            memcpy(sql, data, size);
            sql[size] = '\0'; // Null-terminate the input data

            // Execute the input data as an SQL statement
            rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
            if (rc != SQLITE_OK) {
                sqlite3_free(errMsg);
            }

            free(sql);
        }
    }

    // Call the function-under-test
    sqlite3_db_cacheflush(db);

    // Clean up and close the database
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

    LLVMFuzzerTestOneInput_48(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
