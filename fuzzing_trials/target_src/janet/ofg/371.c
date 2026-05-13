#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_371(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a Janet value and an int32_t
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize a Janet value from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Extract an int32_t from the input data
    int32_t index;
    memcpy(&index, data + sizeof(Janet), sizeof(int32_t));

    // Ensure that the Janet value is valid
    if (!janet_checktype(janet_value, JANET_ARRAY)) {
        janet_deinit();
        return 0;
    }

    // Retrieve the array from the Janet value
    JanetArray *array = janet_unwrap_array(janet_value);

    // Ensure the index is within bounds
    if (index < 0 || index >= array->count) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    uint64_t result = janet_getuinteger64(&array->data[index], index);

    // Use the result to prevent compiler optimizations (if needed)
    (void)result;

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_371(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
