#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "magic.h"
#include <iostream>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // No need to proceed with empty input
    }

    struct magic_set *ms;

    // Initialize a magic set
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        std::cerr << "Failed to initialize magic set." << std::endl;
        return 0;
    }

    // Load a magic database from the default location
    if (magic_load(ms, NULL) != 0) {
        std::cerr << "Failed to load magic database: " << magic_error(ms) << std::endl;
        magic_close(ms);
        return 0;
    }

    // Ensure the data is null-terminated
    char *null_terminated_data = new char[size + 1];
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Use the provided data as input to the function under test
    const char *result = magic_buffer(ms, null_terminated_data, size);

    // Check if the result is valid and log it
    if (result != NULL) {
        // Log the result to ensure the function is exercised
        std::cout << "Magic Buffer Result: " << result << std::endl;
    } else {
        std::cerr << "Magic buffer returned NULL: " << magic_error(ms) << std::endl;
    }

    // Clean up
    magic_close(ms);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
