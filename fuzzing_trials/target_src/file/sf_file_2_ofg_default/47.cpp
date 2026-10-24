#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>  // Include this for 'stderr' and 'fprintf'

extern "C" {
    const char * magic_buffer(struct magic_set *, const void *, size_t);
    struct magic_set *magic_open(int flags);
    int magic_load(struct magic_set *ms, const char *filename);
    void magic_close(struct magic_set *ms);
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a magic set
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        fprintf(stderr, "Failed to initialize magic set\n");
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(magic));
        magic_close(magic);
        return 0;
    }

    // Ensure the data is not null by checking size and data pointer
    if (data != NULL && size > 0) {
        // Call the function-under-test
        const char *result = magic_buffer(magic, data, size);

        // Check the result (optional, for debugging purposes)
        if (result != NULL) {
            // Log the result for debugging purposes
            fprintf(stderr, "Magic result: %s\n", result);
        } else {
            fprintf(stderr, "Magic buffer returned NULL: %s\n", magic_error(magic));
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
