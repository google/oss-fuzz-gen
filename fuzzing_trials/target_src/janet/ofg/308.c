#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include for memcpy
#include "janet.h" // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_308(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a Janet number
    if (size < sizeof(double)) {
        return 0;
    }

    // Initialize a Janet variable
    Janet janet_value;

    // Assuming Janet is a union or struct that can hold a double
    double number;
    memcpy(&number, data, sizeof(double));
    janet_value = janet_wrap_number(number);

    // Call the function-under-test
    double result = janet_unwrap_number(janet_value);

    // Optionally print the result for debugging purposes
    printf("Unwrapped number: %f\n", result);

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

    LLVMFuzzerTestOneInput_308(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
