#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h> // Include limits.h for INT32_MAX

// Function-under-test declaration
int janet_scan_int64(const uint8_t *data, int32_t length, int64_t *output);

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Ensure size is non-zero and within a reasonable range for int32_t
    if (size == 0 || size > INT32_MAX) {
        return 0;
    }

    int32_t length = (int32_t)size;
    int64_t output = 0;

    // Call the function-under-test
    janet_scan_int64(data, length, &output);

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

    LLVMFuzzerTestOneInput_143(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
