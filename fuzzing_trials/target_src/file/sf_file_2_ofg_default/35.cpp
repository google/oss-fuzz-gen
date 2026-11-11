#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure the input size is non-zero for meaningful processing
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set structure with error reporting
    struct magic_set *magic = magic_open(MAGIC_NONE | MAGIC_ERROR);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        magic_close(magic);
        return 0;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, buffer, size);

    // Use the result to prevent compiler optimizations from removing the call
    if (result != NULL) {
        std::cout << "Magic result: " << result << std::endl; // Output the result for debugging
        volatile int dummy = 0;
        dummy += result[0]; // Use the result in a non-trivial way
    } else {
        std::cerr << "Magic buffer returned NULL" << std::endl; // Log if result is NULL
    }

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
