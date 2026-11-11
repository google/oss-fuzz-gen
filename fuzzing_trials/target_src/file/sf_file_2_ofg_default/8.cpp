#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <stdio.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Skip empty inputs
    }

    // Ensure data is null-terminated for safety with certain functions
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (!null_terminated_data) {
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        free(null_terminated_data);
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        free(null_terminated_data);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, null_terminated_data, size);

    // Use result in a meaningful way to affect program behavior
    if (result != NULL) {
        // Print the result to ensure the function is being called with varying inputs
        printf("Magic result: %s\n", result);

        // Example of using the result to affect behavior
        if (strstr(result, "text") != NULL) {
            // Perform some action if the result indicates text
            printf("Detected text format.\n");
        } else if (strstr(result, "image") != NULL) {
            // Perform some action if the result indicates an image
            printf("Detected image format.\n");
        } else {
            // Handle other types to ensure diverse code paths
            printf("Detected other format: %s\n", result);
        }
    } else {
        // Ensure that the function is being called even when result is NULL
        printf("Magic result is NULL\n");
    }

    // Clean up
    magic_close(magic);
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
