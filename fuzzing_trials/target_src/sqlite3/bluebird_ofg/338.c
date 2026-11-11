#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_338(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize SQLite
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // Failed to open in-memory database
    }

    // Extract an integer from the data for the 'op' parameter
    int op = *(const int *)data;

    // Extract a string for the 'zDbName' parameter
    const char *zDbName = (const char *)(data + sizeof(int));

    // Ensure null-termination of the string
    size_t zDbNameLen = strnlen(zDbName, size - sizeof(int));
    char *zDbNameCopy = (char *)malloc(zDbNameLen + 1);
    if (!zDbNameCopy) {
        sqlite3_close(db);
        return 0; // Memory allocation failed
    }
    memcpy(zDbNameCopy, zDbName, zDbNameLen);
    zDbNameCopy[zDbNameLen] = '\0';

    // Use the remaining data as the 'pArg' parameter
    void *pArg = (void *)(data + sizeof(int) + zDbNameLen + 1);

    // Call the function-under-test
    sqlite3_file_control(db, zDbNameCopy, op, pArg);

    // Clean up
    free(zDbNameCopy);
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

    LLVMFuzzerTestOneInput_338(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
