#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h> // Include this to ensure INT32_MAX is defined

// Assume the function is declared in an external library
extern int janet_scan_uint64(const uint8_t *data, int32_t size, uint64_t *result);

int LLVMFuzzerTestOneInput_361(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero and within the range of int32_t
    if (size == 0 || size > INT32_MAX) {
        return 0;
    }

    // Initialize the result variable
    uint64_t result = 0;

    // Call the function-under-test
    int ret = janet_scan_uint64(data, (int32_t)size, &result);

    // Optionally, print the result and return value for debugging purposes
    // printf("Return: %d, Result: %" PRIu64 "\n", ret, result);

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

    LLVMFuzzerTestOneInput_361(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
