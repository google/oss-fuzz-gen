#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <cstdio>  // Include the C++ header for printf

extern "C" {
    // Include the necessary headers for the function-under-test
    #include "magic.h"
}

// Define MAGIC_PARAM_MAX if it's not defined in the included headers
#ifndef MAGIC_PARAM_MAX
#define MAGIC_PARAM_MAX 10 // Assuming a default value, replace with correct one if known
#endif

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    struct magic_set *magic = magic_open(MAGIC_NONE);
    int param = 0;
    int *value = (int *)malloc(sizeof(int)); // Allocate memory for the value

    if (magic == NULL || value == NULL) {
        if (magic != NULL) {
            magic_close(magic);
        }
        free(value);
        return 0; // Exit if memory allocation failed
    }

    // Ensure the magic_set is initialized
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        free(value);
        return 0;
    }

    // Use the input data to affect the behavior of the function under test
    if (size > 0) {
        // Use the first byte of data as a parameter for magic_getparam
        param = data[0] % MAGIC_PARAM_MAX;
    }

    // Call the function-under-test
    if (magic_getparam(magic, param, value) == -1) {
        // Handle error if magic_getparam fails
        magic_close(magic);
        free(value);
        return 0;
    }

    // Optionally, use the rest of the data to influence the behavior of the magic library
    if (size > 1) {
        // Use the rest of the data as a buffer to identify
        const char *result = magic_buffer(magic, data + 1, size - 1);
        if (result) {
            // Do something with the result if needed
            // For example, print the result to ensure it's being used
            printf("Magic result: %s\n", result);
        }
    }

    // Clean up
    magic_close(magic);
    free(value);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
