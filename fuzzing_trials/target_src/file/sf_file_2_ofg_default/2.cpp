#include <cstdint>
#include <cstdlib>
#include <magic.h>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    struct magic_set *ms;
    const char *result;

    // Initialize the magic library
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        std::cerr << "Failed to initialize magic library" << std::endl;
        return 0;
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        std::cerr << "Failed to load magic database: " << magic_error(ms) << std::endl;
        magic_close(ms);
        return 0;
    }

    // Convert the input data to a null-terminated string to ensure it's processed correctly
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    result = magic_buffer(ms, buffer, size);

    // Check result to ensure it's not null
    if (result != NULL) {
        // Optionally print the result for debugging
        std::cout << "Magic: " << result << std::endl;
    } else {
        std::cerr << "Magic buffer returned null: " << magic_error(ms) << std::endl;
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
