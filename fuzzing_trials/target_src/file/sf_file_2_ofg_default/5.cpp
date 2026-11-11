#include <stddef.h>
#include <stdint.h>
#include <magic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    struct magic_set *ms;
    const char *result;

    // Initialize a magic_set object
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure that the input data is non-empty and valid
    if (size > 0 && data != NULL) {
        // Allocate a buffer to ensure null-terminated data
        char *buffer = (char *)malloc(size + 1);
        if (buffer == NULL) {
            magic_close(ms);
            return 0;
        }

        // Copy data to buffer and null-terminate it
        memcpy(buffer, data, size);
        buffer[size] = '\0';

        // Call the function-under-test
        result = magic_buffer(ms, buffer, size);

        // Handle the result to ensure the function is fully exercised
        if (result != NULL) {
            // For demonstration, we could print the result, but in fuzzing, we typically don't.
            // printf("Magic result: %s\n", result);
        } else {
            // Handle the error case where result is NULL
            const char *error = magic_error(ms);
            if (error != NULL) {
                // For debugging purposes, we could log the error
                // printf("Magic error: %s\n", error);
            }
        }

        // Free the allocated buffer
        free(buffer);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
