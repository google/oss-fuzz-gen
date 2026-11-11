#include <stdint.h>
#include <stddef.h>

// Function signature for the function-under-test
int janet_scan_number_base(const uint8_t *input, int32_t len, int32_t base, double *out);

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the function parameters
    if (size < sizeof(int32_t) + sizeof(int32_t)) {
        return 0;
    }

    // Extract len and base from the input data
    int32_t len = (int32_t)(data[0] % 256); // Ensure len is within a reasonable range
    int32_t base = (int32_t)(data[1] % 36); // Base should be between 0 and 35

    // Ensure len does not exceed the remaining data size
    if (len > (int32_t)(size - 2)) {
        len = (int32_t)(size - 2);
    }

    // Prepare the output variable
    double out = 0.0;

    // Call the function-under-test
    janet_scan_number_base(data + 2, len, base, &out);

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

    LLVMFuzzerTestOneInput_178(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
