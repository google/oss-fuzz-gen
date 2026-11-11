#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <stdio.h> // Include the necessary header for 'stderr'

extern "C" {
    // Include the function-under-test here
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Check if the input data is non-empty
    if (size == 0) {
        return 0; // Return early if there's no data to process
    }

    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Return if magic_open fails
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Return if magic_load fails
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Check the result (optional, for debugging purposes)
    if (result != NULL) {
        // Optionally print or log the result
        // For example, logging the result to stderr for debugging
        fprintf(stderr, "Magic buffer result: %s\n", result);
    } else {
        // Log an error if the result is NULL to indicate a problem
        fprintf(stderr, "Error: magic_buffer returned NULL\n");

        // Attempt to reload the magic database in case of failure
        if (magic_load(magic, NULL) == 0) {
            // Retry calling the function-under-test
            result = magic_buffer(magic, (const void *)data, size);
            if (result != NULL) {
                fprintf(stderr, "Retry successful: Magic buffer result: %s\n", result);
            } else {
                fprintf(stderr, "Retry failed: magic_buffer returned NULL again\n");
            }
        } else {
            fprintf(stderr, "Error: magic_load failed during retry\n");
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
