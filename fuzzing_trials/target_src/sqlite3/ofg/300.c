#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_300(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        return 0; // If opening the database fails, exit early
    }

    // Create a table
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS fuzz_table (id INTEGER PRIMARY KEY, content TEXT);", NULL, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Use the input data as an SQL command
    if (size > 0) {
        // Prepare a SQL statement using the input data
        char *sql = sqlite3_mprintf("%.*s", (int)size, data);
        rc = sqlite3_exec(db, sql, NULL, 0, &errMsg);
        sqlite3_free(sql); // Free the SQL string

        if (rc != SQLITE_OK) {
            sqlite3_free(errMsg);
        }
    }

    // Reset auto extension (though it does not take parameters, it is part of the test)
    sqlite3_reset_auto_extension();

    // Close the database
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

    LLVMFuzzerTestOneInput_300(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
