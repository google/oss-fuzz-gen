#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio> // Include the C standard I/O library for printf

extern "C" {
    #include <magic.h> // Wrap the C library include in extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Check if the input size is greater than zero to ensure non-null input
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set instance
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, return early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, return early
    }

    // Call the function-under-test directly using the data buffer
    const char *result = magic_buffer(magic, data, size);

    // Check the result for errors
    if (result == NULL) {
        // Handle the error case, possibly by logging or further processing
        const char *error = magic_error(magic);
        if (error != NULL) {
            fprintf(stderr, "Magic error: %s\n", error);
        }
    } else {
        // For this example, we will just print the result
        // In a real fuzzing scenario, this might not be necessary
        printf("Magic buffer result: %s\n", result);
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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
