#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Assuming the Janet library provides this header

// Remove the 'extern "C"' linkage specification since this is C code, not C++
int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t from the input data
    int32_t input_integer;
    // Copy the first 4 bytes from data into input_integer
    input_integer = *(const int32_t *)data;

    // Call the function-under-test
    Janet result = janet_wrap_integer(input_integer);

    // Optionally use the result to avoid compiler optimizations removing the call
    // This is just a dummy operation to use the result
    if (janet_checktype(result, JANET_NUMBER)) {
        double number = janet_unwrap_number(result);
        (void)number; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_75(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
