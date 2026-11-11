#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Ensure that the Janet library is included

// Remove the 'extern "C"' as this is C code, not C++
int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a Janet object from the input data
    Janet janet_input;
    if (size >= sizeof(double)) {
        // Use the first few bytes of data to create a Janet object
        janet_input = janet_wrap_number(*(double *)data);
    } else {
        // Fallback to a default Janet object if data is insufficient
        janet_input = janet_wrap_nil();
    }

    // Call the function-under-test
    JanetString result = janet_to_string(janet_input);

    // Use the result to avoid compiler optimizations removing the call
    if (result) {
        // Just a dummy operation to use the result
        (void)result[0];
    }

    // Deinitialize Janet runtime
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

    LLVMFuzzerTestOneInput_40(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
