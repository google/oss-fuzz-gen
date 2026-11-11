#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "janet.h"  // Assuming this is the header file where JanetArray is defined

// Mock function for janet_array_ensure_386 if it's not available
void janet_array_ensure_386(JanetArray *array, int32_t capacity, int32_t growth) {
    if (array->capacity < capacity) {
        array->capacity = capacity + growth;
        array->data = realloc(array->data, array->capacity * sizeof(Janet));
    }
}

int LLVMFuzzerTestOneInput_386(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t) * 2) {
        return 0; // Not enough data to extract two int32_t values
    }

    // Extract int32_t values from the input data
    int32_t capacity = *((int32_t *)data);
    int32_t growth = *((int32_t *)(data + sizeof(int32_t)));

    // Initialize a JanetArray
    JanetArray array;
    array.capacity = 0;
    array.count = 0;
    array.data = NULL;

    // Call the function-under-test
    janet_array_ensure_386(&array, capacity, growth);

    // Cleanup
    free(array.data);

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

    LLVMFuzzerTestOneInput_386(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
