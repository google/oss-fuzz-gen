#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT);"
                      "INSERT INTO test (name) VALUES ('Alice');"
                      "SELECT * FROM test;";
    
    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Execute the SQL statement
    rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a statement
    rc = sqlite3_prepare_v2(db, "SELECT * FROM test;", -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Ensure the data size is sufficient for an integer index
    if (size < sizeof(int)) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Use the first 4 bytes of data as an integer index
    int index;
    memcpy(&index, data, sizeof(int));

    // Call the function-under-test
    const char *column_name = sqlite3_column_name(stmt, index);

    // Print the column name if it is not NULL
    if (column_name != NULL) {
        printf("Column name: %s\n", column_name);
    }

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

    LLVMFuzzerTestOneInput_261(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
