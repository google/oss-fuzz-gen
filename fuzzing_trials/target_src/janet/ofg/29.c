#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a Janet object from the fuzz data
    Janet janet_value;
    if (size >= sizeof(Janet)) {
        janet_value = *(Janet *)data;
    } else {
        // If the size is less than a Janet object, fill with default
        janet_value = janet_wrap_nil();
    }

    // Call the function-under-test
    JanetCFunction result = janet_unwrap_cfunction(janet_value);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_29(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
