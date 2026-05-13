#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include this library for malloc and free
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_393(const uint8_t *data, size_t size) {
    // Ensure there is enough data for two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Find a midpoint to split the data into two strings
    size_t midpoint = size / 2;

    // Allocate memory for the two strings and ensure they are null-terminated
    char *pattern = (char *)malloc(midpoint + 1);
    char *string = (char *)malloc(size - midpoint + 1);

    if (pattern == NULL || string == NULL) {
        free(pattern);
        free(string);
        return 0;
    }

    // Copy data into the strings
    memcpy(pattern, data, midpoint);
    pattern[midpoint] = '\0';

    memcpy(string, data + midpoint, size - midpoint);
    string[size - midpoint] = '\0';

    // Call the function under test
    sqlite3_strglob(pattern, string);

    // Free allocated memory
    free(pattern);
    free(string);

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

    LLVMFuzzerTestOneInput_393(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
