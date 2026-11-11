#include <cstdint> // For uint8_t
#include <cstddef> // For size_t
#include <cstdlib> // For NULL
#include <cstring> // For memcpy
#include <iostream> // For std::cerr

extern "C" {
    #include <magic.h>
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Create a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        std::cerr << "Failed to initialize magic library\n";
        return 0; // If magic_open fails, return immediately
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        std::cerr << "Failed to load magic database: " << magic_error(magic) << "\n";
        magic_close(magic);
        return 0; // If magic_load fails, clean up and return
    }

    // Ensure size is not zero
    if (size == 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test using magic_buffer
    const char *result = magic_buffer(magic, data, size);

    // Check the result and print it for debugging purposes
    if (result != NULL) {
        std::cerr << "Magic buffer result: " << result << "\n";
    } else {
        std::cerr << "Magic buffer error: " << magic_error(magic) << "\n";
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
