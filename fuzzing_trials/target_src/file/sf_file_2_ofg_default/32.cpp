#include <stdint.h>
#include <stddef.h>
#include <magic.h>

extern "C" {
    // Function-under-test declaration
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure with error checking
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, return early
    }

    // Load default magic database with error checking
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, return early
    }

    // Ensure the data is not empty to effectively invoke the function under test
    if (size > 0) {
        // Call the function-under-test
        const char *result = magic_buffer(magic, data, size);

        // Use the result in some way to avoid unused variable warning
        if (result != NULL) {
            // For fuzzing purposes, we don't need to do anything with the result
            // but we can print it for debugging purposes
            // printf("Magic result: %s\n", result); // Uncomment for debugging
        }
    } else {
        // If size is 0, provide a default non-null input to test the function
        // Instead of using a static default, construct a dynamic default input
        const char default_data[] = "default";
        const char *result = magic_buffer(magic, default_data, sizeof(default_data) - 1);

        if (result != NULL) {
            // For fuzzing purposes, we don't need to do anything with the result
            // but we can print it for debugging purposes
            // printf("Magic result: %s\n", result); // Uncomment for debugging
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
