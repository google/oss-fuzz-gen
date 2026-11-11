#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid sqlite3_value
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the sqlite3_value
    sqlite3_value *value;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // Initialize an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy statement to obtain a sqlite3_value object
    rc = sqlite3_prepare_v2(db, "SELECT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the input data to the statement
    sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);

    // Step the statement to initialize the value
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Get the sqlite3_value object
        value = (sqlite3_value *)sqlite3_column_value(stmt, 0);

        // Call the function-under-test
        int numericType = sqlite3_value_numeric_type(value);

        // Use the numericType value to avoid compiler optimizations
        (void)numericType;
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

    LLVMFuzzerTestOneInput_175(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
