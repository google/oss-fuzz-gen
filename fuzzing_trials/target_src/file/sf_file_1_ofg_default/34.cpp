#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure size is non-zero to avoid invalid access and that data is not null
    if (size == 0 || data == NULL) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test directly with the buffer
    const char *result = magic_buffer(ms, data, size);

    // Check if result is not null and perform some operation to ensure it's used
    if (result != NULL) {
        // Log the result or perform a more complex operation to ensure it's used
        std::cout << "Magic result: " << result << std::endl;

        // Perform additional operations based on the result to increase coverage
        if (std::string(result).find("text") != std::string::npos) {
            // Simulate handling text files
            volatile int text_dummy = 0;
            for (size_t i = 0; i < size; ++i) {
                text_dummy += data[i];
            }
        } else if (std::string(result).find("image") != std::string::npos) {
            // Simulate handling image files
            volatile int image_dummy = 0;
            for (size_t i = 0; i < size; i += 2) {
                image_dummy += data[i];
            }
        }
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
