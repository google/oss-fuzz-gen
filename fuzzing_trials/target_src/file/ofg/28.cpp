#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <cstdio> // For optional debugging output

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Check if the input data is not empty
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Open the magic database with default flags
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, data, size);

    // Check the result
    if (result != NULL) {
        // Optionally, you can print the result for debugging
        // printf("Magic result: %s\n", result);
    } else {
        // Handle the case where magic_buffer returns an error
        const char *error = magic_error(magic);
        if (error != NULL) {
            // Optionally, you can print the error for debugging
            // printf("Magic error: %s\n", error);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
