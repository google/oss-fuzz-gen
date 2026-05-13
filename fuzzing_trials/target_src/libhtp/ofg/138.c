#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function-under-test declaration
int bstr_util_cmp_mem(const void *mem1, size_t size1, const void *mem2, size_t size2);

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure there is enough data for two non-empty memory segments
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for comparison
    size_t size1 = size / 2;
    size_t size2 = size - size1;

    const void *mem1 = data;
    const void *mem2 = data + size1;

    // Call the function-under-test
    int result = bstr_util_cmp_mem(mem1, size1, mem2, size2);

    // Use the result to prevent compiler optimizations that remove the call
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
