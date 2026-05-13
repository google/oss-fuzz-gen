#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

extern int janet_bytes_view(Janet, const uint8_t **, int32_t *);

int LLVMFuzzerTestOneInput_316(const uint8_t *data, size_t size) {
    Janet janet_value;
    const uint8_t *byte_view = NULL;
    int32_t length = 0;

    // Ensure that the size is sufficient to create a Janet string or buffer
    if (size < 1) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a Janet string from the input data
    janet_value = janet_stringv(data, size);

    // Call the function-under-test
    janet_bytes_view(janet_value, &byte_view, &length);

    // Clean up the Janet environment
    janet_deinit();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_316(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
