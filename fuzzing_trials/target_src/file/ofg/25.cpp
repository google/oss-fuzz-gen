#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load a magic database (if needed, you can specify a path to a magic file)
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Use the magic_set for some operation (e.g., magic_buffer)
    if (size > 0) {
        // Ensure the data is null-terminated for safety
        char *null_terminated_data = (char *)malloc(size + 1);
        if (null_terminated_data == NULL) {
            magic_close(magic);
            return 0;
        }
        memcpy(null_terminated_data, data, size);
        null_terminated_data[size] = '\0';

        // Call magic_buffer with the data
        const char *result = magic_buffer(magic, null_terminated_data, size);
        if (result != NULL) {
            // Process the result to ensure the function is exercised
            // For example, log the result
            printf("Magic result: %s\n", result);
        } else {
            // Log an error if the result is NULL
            printf("Magic buffer returned NULL\n");
        }

        free(null_terminated_data);
    } else {
        // Handle zero-length inputs by passing a non-null small input to magic_buffer
        const char *result = magic_buffer(magic, " ", 1); // Changed input to a space character
        if (result != NULL) {
            printf("Magic result for zero-length input: %s\n", result);
        } else {
            printf("Magic buffer returned NULL for zero-length input\n");
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
