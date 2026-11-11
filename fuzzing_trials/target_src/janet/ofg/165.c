#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Fuzzing harness for janet_get_abstract_type
int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a Janet object from the input data
    Janet janet_obj;
    if (size >= sizeof(Janet)) {
        // Ensure we have enough data to fill a Janet object
        janet_obj = *(const Janet *)data;
    } else {
        // If not enough data, initialize with a default value
        janet_obj = janet_wrap_nil();
    }

    // Call the function-under-test
    const JanetAbstractType *abstract_type = janet_get_abstract_type(janet_obj);

    // Use the result to avoid compiler optimizations
    if (abstract_type) {
        // Do something with abstract_type if needed
    }

    // Deinitialize Janet
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

    LLVMFuzzerTestOneInput_165(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
