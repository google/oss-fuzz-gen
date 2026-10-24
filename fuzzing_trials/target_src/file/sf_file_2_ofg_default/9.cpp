#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Check if the input data is not empty
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        // If magic_open fails, return immediately
        return 0;
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        // If magic_load fails, cleanup and return
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test with the provided data and size
    const char *result = magic_buffer(ms, data, size);

    // Use the result to prevent it from being optimized away
    if (result != NULL) {
        // Print the result to ensure the function is exercised
        std::cout << "Magic result: " << result << std::endl;
    } else {
        // If result is NULL, print an error message
        std::cout << "Magic result is NULL" << std::endl;
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
