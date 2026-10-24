#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the input data is not null and has a reasonable size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize the magic library
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        std::cerr << "Failed to initialize magic library" << std::endl;
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        std::cerr << "Failed to load magic database: " << magic_error(magic) << std::endl;
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Use the result to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Log or process the result to ensure the function is being utilized
        // Print the result to ensure the function is being utilized
        std::cout << "Magic Result: " << result << std::endl;
    } else {
        std::cerr << "Magic buffer error: " << magic_error(magic) << std::endl;
    }

    // Clean up resources
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
