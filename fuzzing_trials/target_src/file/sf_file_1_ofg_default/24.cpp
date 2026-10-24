#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Initialize a magic_set object
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        fprintf(stderr, "Failed to initialize magic library\n");
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(ms));
        magic_close(ms);
        return 0;
    }

    // Ensure the size is not zero to avoid passing a potentially invalid buffer
    if (size > 0) {
        // Call the function-under-test
        const char *result = magic_buffer(ms, data, size);

        // Check if the result is not NULL and print it to ensure it's being used
        if (result != NULL) {
            printf("Magic buffer result: %s\n", result);
        } else {
            fprintf(stderr, "Magic buffer returned NULL: %s\n", magic_error(ms));
        }
    } else {
        fprintf(stderr, "Input size is zero\n");
    }

    // Clean up the magic_set object
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
