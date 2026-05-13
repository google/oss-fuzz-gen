#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int janet_scan_numeric(const uint8_t *data, int32_t len, Janet *out);

int LLVMFuzzerTestOneInput_366(const uint8_t *data, size_t size) {
    // Ensure size is within int32_t range
    if (size > INT32_MAX) {
        return 0;
    }

    // Initialize a Janet variable to store the result
    Janet result;

    // Call the function-under-test
    janet_scan_numeric(data, (int32_t)size, &result);

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

    LLVMFuzzerTestOneInput_366(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
