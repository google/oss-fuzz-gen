#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <cstring>
#include <iostream>

extern "C" {
    // Include the necessary headers and function declarations for the project-under-test.
    int magic_errno(struct magic_set *);
    const char *magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure that the data is not null and size is greater than zero
    if (data == NULL || size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load a default magic database
    if (magic_load(magic, "/usr/share/misc/magic.mgc") != 0) {
        magic_close(magic);
        return 0;
    }

    // Use the data to perform a magic check
    const char *result = magic_buffer(magic, data, size);
    if (result == NULL) {
        // Handle error
        int err = magic_errno(magic);
        std::cerr << "Error: " << err << std::endl;
    } else {
        // Optionally, perform some operation with the result to ensure it is used
        size_t result_length = strlen(result);
        if (result_length > 0) {
            // Log the result to ensure it's being used
            std::cout << "Magic result: " << result << std::endl;
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
