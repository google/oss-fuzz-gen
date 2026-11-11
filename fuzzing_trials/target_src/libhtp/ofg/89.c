#include <stddef.h>
#include <stdint.h>

extern int bstr_util_mem_index_of_mem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for the function-under-test
    const void *haystack = data;
    size_t haystack_len = size;

    // Ensure the needle is not NULL and has a length greater than 0
    const void *needle = (size > 1) ? data + 1 : data;
    size_t needle_len = (size > 1) ? size - 1 : 1;

    // Call the function-under-test
    int result = bstr_util_mem_index_of_mem(haystack, haystack_len, needle, needle_len);

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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
