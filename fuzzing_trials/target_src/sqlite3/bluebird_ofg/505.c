#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>

// Dummy callback functions for the sqlite3_create_function parameters
void dummy_func(sqlite3_context *context, int argc, sqlite3_value **argv) {
    // Do nothing
}

void dummy_step(sqlite3_context *context, int argc, sqlite3_value **argv) {
    // Do nothing
}

void dummy_final(sqlite3_context *context) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_505(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        return 0; // Failed to open database
    }

    // Prepare a function name from the input data
    size_t name_len = size < 100 ? size : 100; // Limit function name length
    char func_name[101];
    memcpy(func_name, data, name_len);
    func_name[name_len] = '\0'; // Ensure null-termination

    // Call the function-under-test
    rc = sqlite3_create_function(db, func_name, 1, SQLITE_UTF8, NULL, dummy_func, dummy_step, dummy_final);

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

    LLVMFuzzerTestOneInput_505(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
