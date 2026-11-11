#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <iostream>
#include <cstring>

extern "C" {
    // Include the function-under-test
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // Exit if magic_open fails
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // Exit if magic_load fails
    }

    // Ensure that the input data is not empty
    if (size == 0) {
        magic_close(ms);
        return 0;
    }

    // Create a buffer to ensure null-terminated input for magic_buffer
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        magic_close(ms);
        return 0;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    const char *result = magic_buffer(ms, buffer, size);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Print the result to ensure it is used
        std::cout << "Magic result: " << result << std::endl;
    }

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
