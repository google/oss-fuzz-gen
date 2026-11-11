#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <cstdio> // Include the C++ header for printf

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    struct magic_set *magic = NULL;
    const char *result;

    // Initialize the magic_set structure
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the magic database
    // Use a real path to the magic database or ensure the environment is set up correctly
    if (magic_load(magic, NULL) != 0) {
        std::fprintf(stderr, "Failed to load magic database: %s\n", magic_error(magic));
        magic_close(magic);
        return 0;
    }

    // Ensure the data is not empty and has a valid size
    if (data == NULL || size == 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test with the provided data
    result = magic_buffer(magic, data, size);

    // Ensure the result is not NULL before using it
    if (result != NULL) {
        // For fuzzing purposes, we just ensure the function is called
        // Log the result to increase code coverage
        volatile size_t result_length = strlen(result);
        (void)result_length;

        // Additional logging to ensure the result is utilized
        std::printf("Magic result: %s\n", result); // Use std::printf for C++ compatibility
    } else {
        std::fprintf(stderr, "Magic buffer returned NULL: %s\n", magic_error(magic));
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
