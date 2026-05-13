#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stddef.h> // Include for NULL

// Function to initialize a SQLite statement for fuzzing
static sqlite3_stmt* initialize_statement() {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT * FROM test WHERE id = ?";

    // Open a temporary in-memory database
    if (sqlite3_open(":memory:", &db) == SQLITE_OK) {
        // Prepare a simple SQL statement with a parameter
        sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    }

    // We do not close the database to keep the statement valid
    return stmt;
}

int LLVMFuzzerTestOneInput_262(const uint8_t *data, size_t size) {
    // Initialize the SQLite statement
    sqlite3_stmt *stmt = initialize_statement();

    // Ensure there is a statement and data is not empty
    if (stmt != NULL && size > 0) {
        // Use the first byte of data as the integer index for the parameter
        int index = data[0] % 256; // Limit index to a reasonable range

        // Call the function-under-test
        const char *param_name = sqlite3_bind_parameter_name(stmt, index);

        // Optionally use the result to avoid compiler optimizations
        if (param_name != NULL) {
            // Do something with param_name if needed
        }
    }

    // Finalize the statement to avoid memory leaks
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_262(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
