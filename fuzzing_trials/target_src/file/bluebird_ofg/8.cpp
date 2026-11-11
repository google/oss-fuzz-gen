#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "magic.h"
#include <string.h>

extern "C" {
    int magic_setparam(struct magic_set *, int, const void *);
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    struct magic_set *ms;
    int param_type;
    const void *param_value;

    // Initialize the magic_set structure
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Ensure the size is sufficient to extract an integer for param_type and at least one byte for param_value
    if (size < sizeof(int) + 1) {
        magic_close(ms);
        return 0;
    }

    // Extract an integer from the data for param_type
    memcpy(&param_type, data, sizeof(int));

    // Set param_value to point to the remaining data
    param_value = (const void *)(data + sizeof(int));

    // Ensure param_value points to valid memory within the bounds of the input data
    if (size - sizeof(int) < sizeof(param_value)) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test
    magic_setparam(ms, param_type, param_value);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
