#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>  // Include for memcpy

// Assuming the function is defined in a C library
extern "C" {
    void lou_registerTableResolver(void (*resolver)(const char *table, const char *path, void *data));
}

// A sample resolver function that the fuzzing harness will use
void sampleResolver(const char *table, const char *path, void *data) {
    // For demonstration purposes, just print the inputs
    printf("Table: %s, Path: %s, Data: %p\n", table, path, data);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to split into meaningful parts
    if (size < 2) {
        return 0;
    }

    // Use the first byte to decide how to call the resolver
    size_t tableLen = data[0] % size;
    size_t pathLen = (size - 1 - tableLen) % size;

    // Ensure the lengths are valid
    if (tableLen + pathLen + 1 > size) {
        return 0;
    }

    // Extract table and path strings from data
    char *table = (char *)malloc(tableLen + 1);
    char *path = (char *)malloc(pathLen + 1);

    if (table == nullptr || path == nullptr) {
        free(table);
        free(path);
        return 0;
    }

    memcpy(table, data + 1, tableLen);
    table[tableLen] = '\0';

    memcpy(path, data + 1 + tableLen, pathLen);
    path[pathLen] = '\0';

    // Call the function-under-test with the sample resolver
    lou_registerTableResolver(sampleResolver);

    // Clean up
    free(table);
    free(path);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
