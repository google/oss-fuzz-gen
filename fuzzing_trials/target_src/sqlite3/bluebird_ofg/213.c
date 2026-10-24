#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "sqlite3.h"

// Callback function to simulate a user-defined function
static void test_function(sqlite3_context *context, int argc, sqlite3_value **argv) {
    if (argc == 1 && sqlite3_value_type(argv[0]) == SQLITE_FLOAT) {
        double value = sqlite3_value_double(argv[0]);
        sqlite3_result_double(context, value);
    }
}

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a double value
    if (size < sizeof(double)) {
        return 0;
    }

    // Extract a double value from the input data
    double value;
    memcpy(&value, data, sizeof(double));

    // Initialize a sqlite3 database and context
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a user-defined function to test sqlite3_result_double
    rc = sqlite3_create_function(db, "test_function", 1, SQLITE_UTF8, NULL, test_function, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare a SQL statement that uses the user-defined function
    rc = sqlite3_prepare_v2(db, "SELECT test_function(?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the double value to the SQL statement
    rc = sqlite3_bind_double(stmt, 1, value);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the SQL statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
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

    LLVMFuzzerTestOneInput_213(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
