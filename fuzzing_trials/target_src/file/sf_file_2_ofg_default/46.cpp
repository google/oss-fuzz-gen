#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <string.h>
#include <stdio.h>

extern "C" {
    #include <stdlib.h>
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Check if the input size is zero
    if (size == 0) {
        return 0;
    }

    // Initialize a magic_set object
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(ms));
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test directly with the input data
    const char *result = magic_buffer(ms, data, size);

    // Check if the result is not null to ensure the function is exercised
    if (result != NULL) {
        // Optionally, print or log the result to verify coverage
        // printf("Magic result: %s\n", result);
    } else {
        fprintf(stderr, "Magic buffer error: %s\n", magic_error(ms));
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
