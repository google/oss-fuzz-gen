#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <iostream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    struct magic_set *ms;
    const char *result;

    // Initialize a magic_set object
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test
    result = magic_buffer(ms, data, size);

    // Check if the result is NULL which indicates an error
    if (result == NULL) {
        std::cerr << "Error: " << magic_error(ms) << std::endl;
        magic_close(ms);
        return 0;
    }

    // Process the result to increase code coverage
    std::string magicResult(result);
    std::cout << "Magic result: " << magicResult << std::endl;

    // Perform some operations on the result
    if (magicResult.find("text") != std::string::npos) {
        std::cout << "Detected text format" << std::endl;
    } else if (magicResult.find("image") != std::string::npos) {
        std::cout << "Detected image format" << std::endl;
    } else if (magicResult.find("audio") != std::string::npos) {
        std::cout << "Detected audio format" << std::endl;
    } else if (magicResult.find("video") != std::string::npos) {
        std::cout << "Detected video format" << std::endl;
    } else {
        std::cout << "Unknown format detected" << std::endl;
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
