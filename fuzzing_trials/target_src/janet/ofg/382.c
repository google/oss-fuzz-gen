#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_382(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Ensure the data is large enough to create a Janet string
    if (size < 1) {
        janet_deinit();
        return 0;
    }

    // Create a Janet string from the input data
    Janet janet_str = janet_stringv((const uint8_t *)data, size);

    // Wrap the Janet string in a Janet value
    Janet janet_value = janet_wrap_string(janet_unwrap_string(janet_str));

    // Attempt to unwrap the Janet value as a function
    // Note: This may not be valid if the input data does not represent a function
    if (janet_checktype(janet_value, JANET_FUNCTION)) {
        JanetFunction *result = janet_unwrap_function(janet_value);
        // Use the result if needed
    }

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_382(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
