#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function-under-test declaration
int bstr_util_cmp_mem(const void *mem1, size_t len1, const void *mem2, size_t len2);

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Split the input data into two parts for comparison
    size_t half_size = size / 2;

    // Ensure that both memory blocks have at least one byte
    size_t len1 = half_size > 0 ? half_size : 1;
    size_t len2 = size - half_size > 0 ? size - half_size : 1;

    // Pointers to the two memory blocks
    const void *mem1 = data;
    const void *mem2 = data + len1;

    // Call the function-under-test
    bstr_util_cmp_mem(mem1, len1, mem2, len2);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
