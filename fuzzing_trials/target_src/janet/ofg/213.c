#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract required parameters
    if (size < sizeof(Janet) + 2 * sizeof(int32_t) + sizeof(double)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize the parameters
    const Janet *janet_ptr = (const Janet *)data;

    // Ensure the janet_ptr is not null and points to a valid Janet array
    if (janet_ptr == NULL || !janet_checktype(*janet_ptr, JANET_ARRAY)) {
        janet_deinit();
        return 0;
    }

    int32_t index1 = *(int32_t *)(data + sizeof(Janet));
    int32_t index2 = *(int32_t *)(data + sizeof(Janet) + sizeof(int32_t));
    double default_value = *(double *)(data + sizeof(Janet) + 2 * sizeof(int32_t));

    // Ensure indices are within a reasonable range
    JanetArray *array = janet_unwrap_array(*janet_ptr);
    if (index1 < 0 || index1 >= array->count || index2 < 0 || index2 >= array->count) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    double result = janet_optnumber(janet_ptr, index1, index2, default_value);

    // Use the result in some way to avoid compiler optimizations
    if (result == 0.0) {
        janet_deinit();
        return 1;
    }

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

    LLVMFuzzerTestOneInput_213(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
