#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_484(const uint8_t *data, size_t size) {
    // Ensure the data is not empty and is null-terminated
    if (size > 0 && data[size - 1] == '\0') {
        sqlite3 *db;
        sqlite3_stmt *stmt;

        // Open a temporary in-memory database
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            return 0;
        }

        // Prepare a dummy statement to get a value object
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of sqlite3_prepare_v2
        if (sqlite3_prepare_v2(db, "SELECT ?", size, &stmt, NULL) != SQLITE_OK) {
        // End mutation: Producer.REPLACE_ARG_MUTATOR
            sqlite3_close(db);
            return 0;
        }

        // Bind the input data to the statement
        if (sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        // Evaluate the statement to get the value
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            // Retrieve the value as a double
            double result = sqlite3_column_double(stmt, 0);
            // Use the result in some way to avoid optimizing it out
            (void)result;
        }

        // Clean up
        sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_484(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
