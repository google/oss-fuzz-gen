#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Assume the function bstr_util_cmp_mem_nocase is defined elsewhere
int bstr_util_cmp_mem_nocase(const void *mem1, size_t len1, const void *mem2, size_t len2);

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Split the input data into two parts for the two memory blocks
    size_t half_size = size / 2;

    // Ensure the two parts are not NULL by allocating at least one byte
    const void *mem1 = data;
    size_t len1 = half_size;

    const void *mem2 = data + half_size;
    size_t len2 = size - half_size;

    // Call the function-under-test
    bstr_util_cmp_mem_nocase(mem1, len1, mem2, len2);

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
