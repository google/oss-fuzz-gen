#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

// The function-under-test
Janet janet_wrap_number_safe(double num);

int LLVMFuzzerTestOneInput_274(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0; // Ensure there's enough data to read a double
    }

    // Extract a double from the input data
    double num;
    memcpy(&num, data, sizeof(double));

    // Call the function-under-test
    Janet result = janet_wrap_number_safe(num);

    // Use the result in some way to prevent compiler optimizations from removing the call
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

    LLVMFuzzerTestOneInput_274(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
