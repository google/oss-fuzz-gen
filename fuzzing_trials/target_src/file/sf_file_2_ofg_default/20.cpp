#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Exit if magic_open fails
    }

    // Load default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Exit if magic_load fails
    }

    // Ensure the input data is null-terminated
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        magic_close(magic);
        return 0;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, buffer, size + 1); // Use size + 1 to include null-terminator for the actual data

    // Check the result and handle potential errors
    if (result != NULL) {
        // Use the result to prevent compiler optimizations
        volatile char dummy = result[0];
        (void)dummy;
    } else {
        // Handle the error case if needed
        const char *error = magic_error(magic);
        if (error != NULL) {
            volatile char dummy = error[0];
            (void)dummy;
        }
    }

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
