#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" {
    // Include necessary C headers and code here
    const char *magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, return early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, return early
    }

    // Ensure the input data is not null and has a reasonable size
    if (data == NULL || size == 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Use the result (if needed for debugging)
    if (result != NULL) {
        // Perform any operations with the result if necessary
        // For example, logging the result for debugging purposes
        // printf("Magic result: %s\n", result); // Uncomment for debugging
    } else {
        // If result is NULL, it may indicate an error or unrecognized data
        // We can log this or handle it as needed
        // printf("Magic buffer returned NULL\n"); // Uncomment for debugging
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
