#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Assume the function is defined somewhere
int bstr_util_cmp_mem_nocase(const void *s1, size_t n1, const void *s2, size_t n2);

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Split the input data into two parts for comparison
    size_t half_size = size / 2;

    // Ensure that both parts have at least one byte to compare
    if (half_size == 0) {
        return 0;
    }

    const void *s1 = (const void *)data;
    size_t n1 = half_size;

    const void *s2 = (const void *)(data + half_size);
    size_t n2 = size - half_size;

    // Call the function under test
    int result = bstr_util_cmp_mem_nocase(s1, n1, s2, n2);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
