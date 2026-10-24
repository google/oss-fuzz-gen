#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <stdio.h>
#include <string.h>

extern "C" {
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Initialize a magic_set object
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // Failed to initialize magic_set
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // Failed to load magic database
    }

    // Ensure data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        magic_close(ms);
        return 0; // No valid input data to process
    }

    // Call the function-under-test with the data directly
    const char *result = magic_buffer(ms, data, size);
    if (result != NULL) {
        printf("Magic buffer result: %s\n", result);
    } else {
        printf("Magic buffer returned NULL\n");
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
