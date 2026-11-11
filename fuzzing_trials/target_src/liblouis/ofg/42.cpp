#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" {
    // Include the header for the function-under-test
    const void * lou_getTable(const char *);
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure the input size is non-zero to create a valid C-string
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the C-string and ensure it's null-terminated
    char *tableName = (char *)malloc(size + 1);
    if (tableName == NULL) {
        return 0;
    }
    memcpy(tableName, data, size);
    tableName[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    const void *result = lou_getTable(tableName);

    // Clean up
    free(tableName);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
