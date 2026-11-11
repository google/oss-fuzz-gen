#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <stdio.h> // Include the necessary header for fprintf and stderr

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <magic.h>
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Check if the input data is non-empty
    if (size == 0) {
        return 0;
    }

    struct magic_set *ms;
    const char *result;

    // Initialize the magic library
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // If magic_open fails, exit the fuzzer
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If magic_load fails, exit the fuzzer
    }

    // Call the function-under-test with a valid input
    result = magic_buffer(ms, data, size);

    // Check the result to ensure the function is doing something
    if (result != NULL) {
        // Log the result for debugging purposes
        fprintf(stderr, "Magic result: %s\n", result);
    } else {
        // Log an error message if the result is NULL
        fprintf(stderr, "Magic returned NULL for given input\n");

        // Attempt to get the error message from the magic library
        const char *error = magic_error(ms);
        if (error != NULL) {
            fprintf(stderr, "Magic error: %s\n", error);
        }
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
