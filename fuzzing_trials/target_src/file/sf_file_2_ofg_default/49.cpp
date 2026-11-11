#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <cstring> // Include for memcpy

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Check if the input size is greater than zero
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

    // Create a buffer to ensure the data is null-terminated
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    const char *result = magic_buffer(ms, buffer, size);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NULL) {
        // Ensure it's not null by accessing it
        volatile const char *volatile_result = result;
        (void)volatile_result;
    } else {
        // Handle the error case where result is NULL
        const char *error = magic_error(ms);
        if (error != NULL) {
            volatile const char *volatile_error = error;
            (void)volatile_error;
        }
    }

    // Clean up
    delete[] buffer;
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
