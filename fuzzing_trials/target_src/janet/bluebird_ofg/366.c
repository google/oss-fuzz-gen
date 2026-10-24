#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h>

int LLVMFuzzerTestOneInput_366(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a copy of the input data to ensure const data is not modified
    uint8_t *data_copy = (uint8_t *)malloc(size);
    if (!data_copy) {
        return 0;
    }
    memcpy(data_copy, data, size);

    // Create a Janet object from the copied input data
    Janet janet_obj;
    // Assuming Janet can be initialized from a memory block
    // This is a placeholder as the actual initialization depends on the Janet API
    janet_obj = janet_wrap_buffer((JanetBuffer*)data_copy);

    // Call the function-under-test with the created Janet object
    janet_mark(janet_obj);

    // Free the copied data
    free(data_copy);

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

    LLVMFuzzerTestOneInput_366(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
