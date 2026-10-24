#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

// Ensure the Janet library is initialized before using it
__attribute__((constructor))
static void initialize_janet_185() {
    janet_init();
}

int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }
    
    // Initialize a Janet variable from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Ensure the index is within a reasonable range
    int32_t index = (size > sizeof(Janet)) ? (int32_t)(data[sizeof(Janet)] % 10) : 0;

    // Check if the Janet value is a valid array or tuple
    if (janet_checktype(janet_value, JANET_ARRAY) || janet_checktype(janet_value, JANET_TUPLE)) {
        JanetArray *array = janet_unwrap_array(janet_value);
        if (index < array->count) {
            // Call the function-under-test with the correct number of arguments
            int result = janet_getboolean(array->data, index);

            (void)result; // Suppress unused variable warning
        }
    }

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

    LLVMFuzzerTestOneInput_185(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
