#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <cstring> // For memcpy

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Initialize a magic_set object with more flags to increase coverage
    struct magic_set *magic = magic_open(MAGIC_MIME_TYPE | MAGIC_CONTINUE | MAGIC_ERROR | MAGIC_RAW);
    if (magic == NULL) {
        return 0; // If magic_open fails, return immediately
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, clean up and return
    }

    // Ensure that the data is not empty
    if (size == 0) {
        magic_close(magic);
        return 0;
    }

    // Make a local copy of the data to ensure it's null-terminated
    // This is important for some functions that expect a C-string
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test directly with the given data
    const char *result = magic_buffer(magic, buffer, size);

    // Check if result is not null and handle it
    if (result != NULL) {
        // Optionally, you can print the result for debugging purposes
        // printf("Magic result: %s\n", result);
    } else {
        // Handle the case where result is null, which might indicate an error
        // printf("Magic result is null.\n");
    }

    // Clean up
    delete[] buffer;
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
