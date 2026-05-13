#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" {
    // Include the necessary headers for the function-under-test
    #include "magic.h"
}

// Fuzzing harness for the function-under-test
extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    struct magic_set *magic = magic_open(MAGIC_NONE);

    // Ensure magic is not NULL
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure the input data is not empty to maximize fuzzing effectiveness
    if (size == 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test with the input data
    const char *result = magic_buffer(magic, data, size);

    // Check the result to ensure the function is exercised
    if (result != NULL) {
        // Optionally print the result for debugging purposes
        // printf("Magic: %s\n", result);
    } else {
        // If result is NULL, print the error message for debugging
        const char *error = magic_error(magic);
        if (error != NULL) {
            // printf("Magic Error: %s\n", error);
        }
    }

    // Clean up
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
