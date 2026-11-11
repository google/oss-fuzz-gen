#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// The janet_unwrap_number is a macro, not a function, so no need to declare it
// The Janet type is already defined in janet.h

int LLVMFuzzerTestOneInput_309(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a Janet value
    if (size < sizeof(double)) {
        return 0;
    }

    // Create a Janet value from the input data
    double num = *((double *)data);
    Janet janet_value = janet_wrap_number(num);

    // Call the function-under-test, which is actually a macro
    double result = janet_unwrap_number(janet_value);

    // Use the result to avoid any compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_309(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
