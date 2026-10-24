#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize a magic_set with more flags to enable additional checks
    struct magic_set *ms = magic_open(MAGIC_MIME | MAGIC_SYMLINK | MAGIC_ERROR);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure the data is not empty and has a valid size
    if (data == NULL || size == 0) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test with a valid size
    // Ensure the data is null-terminated to prevent buffer overflows in C functions
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(ms, buffer, size);

    // Check the result to ensure it's not null
    if (result != NULL) {
        // Optionally, perform further processing with the result
        // For example, logging or additional checks
        // printf("Magic result: %s\n", result); // Uncomment for debugging
    } else {
        // If result is null, log or handle the error
        // printf("Magic buffer returned null.\n"); // Uncomment for debugging
    }

    // Clean up
    delete[] buffer;
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
