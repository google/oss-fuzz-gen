#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_587(const uint8_t *data, size_t size) {
    Janet janet_value;

    // Initialize the Janet runtime
    janet_init();

    // Ensure there's at least one byte to interpret
    if (size > 0) {
        // Create a Janet string from the input data
        janet_value = janet_stringv(data, size);
    } else {
        // Default to an empty string if no data is provided
        janet_value = janet_cstringv("");
    }

    // Call the function-under-test
    int32_t length = janet_length(janet_value);

    // Cleanup the Janet runtime
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

    LLVMFuzzerTestOneInput_587(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
