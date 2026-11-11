#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_367(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for at least one Janet value
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet runtime (if required by the Janet library)
    janet_init();

    // Cast the data to a Janet pointer
    const Janet *janet_data = (const Janet *)data;

    // Check if the data can be interpreted as a valid Janet array or structure
    if (!janet_checktype(*janet_data, JANET_ARRAY) && !janet_checktype(*janet_data, JANET_STRUCT)) {
        janet_deinit(); // Clean up the Janet runtime
        return 0;
    }

    // Use a valid index within the bounds of the Janet array or structure
    int32_t index = 0;
    size_t result = 0;

    if (janet_checktype(*janet_data, JANET_ARRAY)) {
        JanetArray *array = janet_unwrap_array(*janet_data);
        if (index < array->count) {
            result = janet_getsize(janet_data, index);
        }
    } else if (janet_checktype(*janet_data, JANET_STRUCT)) {
        const JanetKV *structure = janet_unwrap_struct(*janet_data);
        size_t structure_count = janet_struct_length(structure);
        if (index < structure_count) {
            result = janet_getsize(janet_data, index);
        }
    }

    // Use the result to avoid unused variable warning
    (void)result;

    // Clean up the Janet runtime
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

    LLVMFuzzerTestOneInput_367(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
