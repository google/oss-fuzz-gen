#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <stdio.h> // Include for debugging output

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Check if size is zero to avoid passing null input
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure the data is null-terminated for safety
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        magic_close(magic);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, null_terminated_data, size);

    // Ensure that the result is not null to increase code coverage
    if (result != NULL) {
        // Print the result for debugging purposes
        printf("Result: %s\n", result);

        // Additional checks to increase code coverage
        // For example, check for specific strings or patterns in the result
        if (strstr(result, "text") != NULL) {
            // Do something if the result contains "text"
            printf("Detected text content.\n");
        }
        if (strstr(result, "image") != NULL) {
            // Do something if the result contains "image"
            printf("Detected image content.\n");
        }
        if (strstr(result, "audio") != NULL) {
            // Do something if the result contains "audio"
            printf("Detected audio content.\n");
        }
        if (strstr(result, "video") != NULL) {
            // Do something if the result contains "video"
            printf("Detected video content.\n");
        }
        // Add more checks as needed to cover different paths
    } else {
        // Print an error message if the result is null
        printf("No result from magic_buffer. Error: %s\n", magic_error(magic));
    }

    // Clean up
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
