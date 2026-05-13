#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize SQLite library
    sqlite3_initialize();

    // Ensure the data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Create a new SQLite database in memory
        sqlite3 *db;
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
        sqlite3_open((const char *)"w", &db);
        // End mutation: Producer.REPLACE_ARG_MUTATOR

        // Create a SQL statement using the input data
        char *sql = sqlite3_mprintf("%.*s", (int)size, (const char*)data);

        // Prepare the SQL statement
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

        if (rc == SQLITE_OK) {
            // Execute the SQL statement
            sqlite3_step(stmt);
            // Finalize the statement to clean up
            sqlite3_finalize(stmt);
        }

        // Free the SQL string
        sqlite3_free(sql);

        // Close the SQLite database
        sqlite3_close(db);
    }

    // Shutdown SQLite library
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
