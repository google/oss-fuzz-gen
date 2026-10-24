#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure that the size is non-zero and use the data to form a buffer
    if (size > 0) {
        // Create a buffer from the input data
        char *buffer = static_cast<char*>(malloc(size + 1));
        if (buffer == NULL) {
            magic_close(ms);
            return 0;
        }
        memcpy(buffer, data, size);
        buffer[size] = '\0';  // Null-terminate the buffer

        // Call the function-under-test
        const char *result = magic_buffer(ms, buffer, size);
        
        // Check the result to ensure the function is exercised
        if (result != NULL) {
            // Simulate some usage of the result to ensure it's processed
            size_t result_length = strlen(result);
            if (result_length > 0) {
                // Use the result in some way to increase code coverage
                printf("Magic result: %s\n", result); // Print the result to increase coverage
                volatile char first_char = result[0]; // Prevent optimization
                (void)first_char; // Suppress unused variable warning
            }
        } else {
            // If result is NULL, print an error message to increase coverage
            printf("Magic returned NULL for the buffer\n");
        }

        // Clean up
        free(buffer);
    } else {
        // If size is zero, print a message to increase coverage
        printf("Input size is zero\n");
    }

    magic_close(ms);

    // Return 0 to indicate successful execution
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
