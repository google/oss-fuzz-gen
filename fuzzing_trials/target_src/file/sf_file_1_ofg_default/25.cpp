#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>  // Include the necessary header for memcpy

extern "C" {
    const char *magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there's enough data to extract an integer
    }

    // Initialize a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Failed to initialize magic_set
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Failed to load magic database
    }

    // Extract an integer from the input data
    int fd = 0;
    memcpy(&fd, data, sizeof(int));

    // Call the function-under-test
    const char *result = magic_descriptor(magic, fd);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
