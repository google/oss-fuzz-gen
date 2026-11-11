#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <iostream>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure the input size is non-zero and meaningful
    if (size == 0) {
        return 0;
    }

    // Create a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        // If magic_open fails, return early
        std::cerr << "Failed to initialize magic library." << std::endl;
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        // If loading the magic database fails, clean up and return
        std::cerr << "Failed to load magic database: " << magic_error(magic) << std::endl;
        magic_close(magic);
        return 0;
    }

    // Ensure the data is null-terminated to avoid undefined behavior
    // Allocate a new buffer with an extra byte for the null terminator
    uint8_t *null_terminated_data = new uint8_t[size + 1];
    std::memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)null_terminated_data, size);

    // Log the result to ensure the function is being called and processed
    if (result != NULL) {
        std::cout << "Magic result: " << result << std::endl;
    } else {
        std::cerr << "Magic returned NULL: " << magic_error(magic) << std::endl;
    }

    // Clean up
    magic_close(magic);
    delete[] null_terminated_data;

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
