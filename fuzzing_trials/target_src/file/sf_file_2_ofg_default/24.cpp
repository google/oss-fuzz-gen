extern "C" {
    #include <magic.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h> // Include the string.h header for strlen
    #include <stdlib.h> // Include the stdlib.h header for malloc and free
}

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Check if the input size is greater than zero to ensure non-null input
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Return if magic_set could not be initialized
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Return if magic database could not be loaded
    }

    // Ensure the data is null-terminated for safe string operations
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        magic_close(magic);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, null_terminated_data, size);

    // Ensure the result is checked to increase code coverage
    if (result != NULL) {
        // Do something with the result to ensure it is utilized
        // For example, check the length of the result
        volatile size_t result_length = strlen(result);
        (void)result_length; // Use result_length to avoid compiler optimization

        // Additional processing to ensure the result is used meaningfully
        if (result_length > 0) {
            // Simulate processing the result string
            for (size_t i = 0; i < result_length; ++i) {
                volatile char c = result[i];
                (void)c; // Use c to avoid compiler optimization
            }
        }
    } else {
        // Handle the case where result is NULL to ensure coverage
        volatile int dummy = 0;
        (void)dummy; // Use dummy to avoid compiler optimization
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
