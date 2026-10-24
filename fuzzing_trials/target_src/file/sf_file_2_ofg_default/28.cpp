#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Check if the input data is non-empty
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set object with more flags to enhance coverage
    struct magic_set *magic = magic_open(MAGIC_MIME_TYPE | MAGIC_SYMLINK | MAGIC_ERROR | MAGIC_DEBUG);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test with the provided data
    const char *result = magic_buffer(magic, data, size);

    // Handle the result if needed (e.g., logging, validating)
    if (result != NULL) {
        // Print the result to ensure different code paths are being executed
        std::cout << "Magic result: " << result << std::endl;
    } else {
        // Handle the error case
        const char *error = magic_error(magic);
        if (error != NULL) {
            std::cerr << "Magic error: " << error << std::endl;
        }
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
