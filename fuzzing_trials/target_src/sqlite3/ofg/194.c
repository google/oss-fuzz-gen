#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 2 to have space for two strings
    if (size < 2) {
        return 0;
    }

    // Find a midpoint to split the data into two strings
    size_t mid = size / 2;

    // Create two null-terminated strings from the input data
    char *pattern = (char *)malloc(mid + 1);
    char *string = (char *)malloc(size - mid + 1);

    if (pattern == NULL || string == NULL) {
        free(pattern);
        free(string);
        return 0;
    }

    memcpy(pattern, data, mid);
    pattern[mid] = '\0';

    memcpy(string, data + mid, size - mid);
    string[size - mid] = '\0';

    // Call the function-under-test
    sqlite3_strglob(pattern, string);

    // Clean up
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

    LLVMFuzzerTestOneInput_194(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
