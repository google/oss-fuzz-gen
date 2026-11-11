#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_563(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(int)) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize parameters
    const Janet *janet_data = (const Janet *)data;
    int32_t n = *((int32_t *)(data + sizeof(Janet)));
    int32_t def = *((int32_t *)(data + sizeof(Janet) + sizeof(int32_t)));
    int fallback = *((int *)(data + sizeof(Janet) + sizeof(int32_t) * 2));

    // Ensure n is within a valid range
    n = n % (size / sizeof(Janet)); // Adjust n to be within bounds

    // Call the function-under-test
    int result = janet_optboolean(janet_data, n, def, fallback);

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

    LLVMFuzzerTestOneInput_563(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
