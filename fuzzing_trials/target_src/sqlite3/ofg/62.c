#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Initialize a new database connection in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Ensure that the database pointer is not NULL
    if (db != NULL && size > 0) {
        // Create a SQL statement from the input data
        char *sql = (char *)malloc(size + 1);
        if (sql == NULL) {
            sqlite3_close_v2(db);
            return 0;
        }
        memcpy(sql, data, size);
        sql[size] = '\0'; // Null-terminate the SQL string

        // Execute the SQL statement
        sqlite3_exec(db, sql, 0, 0, &errMsg);

        // Free allocated memory for SQL statement
        free(sql);

        // Free any error message
        if (errMsg) {
            sqlite3_free(errMsg);
        }

        // Call the function-under-test
        sqlite3_close_v2(db);
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

    LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
