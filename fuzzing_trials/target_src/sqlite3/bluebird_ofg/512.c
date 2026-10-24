#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_512(const uint8_t *data, size_t size) {
    // Ensure there is at least some data to work with
    if (size == 0) {
        return 0;
    }

    // Initialize an sqlite3_value object
    sqlite3_value *value = NULL;
    sqlite3_initialize();

    // Create a new sqlite3_value from the input data
    // Instead of using sqlite3ValueNew, use sqlite3_bind_blob to set the value
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(NULL, "SELECT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK || stmt == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_shutdown();
        return 0;
    }

    // Bind the input data to the statement
    rc = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_shutdown();
        return 0;
    }

    // Execute the statement to create the value
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        value = sqlite3_column_value(stmt, 0);
    }

    // Call the function-under-test if value is not null
    if (value != NULL) {
        unsigned int subtype = sqlite3_value_subtype(value);
    }

    // Clean up
    sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_512(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
