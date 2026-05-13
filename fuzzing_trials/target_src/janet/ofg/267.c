#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_267(const uint8_t *data, size_t size) {
    // Ensure that the size is at least the size of a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Extract a double from the input data
    double input_double;
    // Copy the bytes from data to input_double
    memcpy(&input_double, data, sizeof(double));

    // Call the function-under-test
    Janet result = janet_nanbox_from_double(input_double);

    // Optionally, use the result to prevent optimizations
    // For example, print the result type (this is just a placeholder)
    janet_type(result);

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

    LLVMFuzzerTestOneInput_267(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
