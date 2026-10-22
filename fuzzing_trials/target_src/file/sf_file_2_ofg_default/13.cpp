#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <cstring>
#include <cstdio>

extern "C" {
    // Include any C headers that might be necessary for the project under test
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure the data is null-terminated for safety
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        magic_close(ms);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(ms, null_terminated_data, size);

    // Check if the result is not null and print it for debugging
    if (result != NULL) {
        // This is just for debugging purposes to ensure the function is being invoked correctly
        fprintf(stderr, "Magic result: %s\n", result);
    } else {
        // If result is null, print the error message from the magic library
        const char *error = magic_error(ms);
        if (error != NULL) {
            fprintf(stderr, "Magic error: %s\n", error);
        }
    }

    // Cleanup
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
