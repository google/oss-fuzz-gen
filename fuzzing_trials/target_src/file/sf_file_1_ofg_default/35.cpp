#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>  // Include this for memcpy
#include <magic.h>

extern "C" {
    // Function signature from the project-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to extract an integer
    }

    // Initialize a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Failed to create magic_set
    }

    // Load a magic database (typically required for magic operations)
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Failed to load magic database
    }

    // Extract an integer from the input data
    int fd = 0;
    memcpy(&fd, data, sizeof(int));

    // Call the function-under-test
    const char *result = magic_descriptor(magic, fd);

    // Print result for debugging purposes
    if (result != NULL) {
        printf("Magic descriptor: %s\n", result);
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
