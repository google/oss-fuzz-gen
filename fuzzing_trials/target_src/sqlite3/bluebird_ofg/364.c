#include <sys/stat.h>
#include <string.h>
#include <stddef.h>  // Include this to define size_t
#include <stdint.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_364(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    int limitCategory;
    int newLimit;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure size is sufficient to extract two integers
    if (size < 2 * sizeof(int)) {
        sqlite3_close(db);
        return 0;
    }

    // Extract limitCategory and newLimit from the input data
    limitCategory = *(int *)data;
    newLimit = *(int *)(data + sizeof(int));

    // Call the function-under-test
    sqlite3_limit(db, limitCategory, newLimit);

    // Close the SQLite database
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

    LLVMFuzzerTestOneInput_364(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
