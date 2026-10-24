extern "C" {
#include <magic.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure the data is not null and has a minimum size for meaningful processing
    if (size > 0) {
        // Call the function-under-test
        const char *result = magic_buffer(magic, data, size);

        // Use the result in some way to avoid compiler optimizations
        if (result != NULL) {
            volatile const char *volatile_result = result;
            (void)volatile_result;
        } else {
            // Handle the case where magic_buffer returns NULL
            // This can happen if the data is not recognized
            volatile const char *volatile_result = "Unrecognized data";
            (void)volatile_result;
        }
    }

    // Additional processing to increase code coverage
    // Attempt to use other magic functions to increase the coverage
    // For example, checking the description or MIME type
    const char *description = magic_descriptor(magic, 0);
    if (description != NULL) {
        volatile const char *volatile_description = description;
        (void)volatile_description;
    }

    const char *mime_type = magic_file(magic, "/dev/null");
    if (mime_type != NULL) {
        volatile const char *volatile_mime_type = mime_type;
        (void)volatile_mime_type;
    }

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
