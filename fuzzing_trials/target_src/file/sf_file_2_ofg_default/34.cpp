#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <iostream>
#include <cstring> // Include for memcpy

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Exit early if the input data is empty
    }

    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, exit early
    }

    // Ensure that the data is not null-terminated by copying it to a new buffer
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)buffer, size);

    if (result != NULL) {
        // Output the result to ensure the function is being exercised
        std::cout << "Magic Result: " << result << std::endl;
    } else {
        // Output an error message if magic_buffer fails to identify the buffer
        std::cerr << "Magic failed to identify the buffer: " << magic_error(magic) << std::endl;
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
