#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int64_t bstr_util_mem_to_pint(const void *mem, size_t mem_size, int base, size_t *processed);

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Ensure we have a non-zero size for processed
    size_t processed = 0;

    // Choose a base for conversion, ensuring it is within a typical range (2 to 36)
    int base = 10;
    if (size > 1) {
        base = (data[0] % 35) + 2; // Base in the range 2 to 36
    }

    // Call the function-under-test
    int64_t result = bstr_util_mem_to_pint((const void *)data, size, base, &processed);

    // Optionally, use the result and processed to prevent any compiler optimizations
    (void)result;
    (void)processed;

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
