#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Assuming the function is defined elsewhere
int bstr_util_mem_index_of_mem_nocase(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Split the input data into two parts: haystack and needle
    // Ensure that both parts are not empty
    if (size < 2) {
        return 0;
    }

    size_t haystack_len = size / 2;
    size_t needle_len = size - haystack_len;

    const void *haystack = data;
    const void *needle = data + haystack_len;

    // Call the function-under-test
    int result = bstr_util_mem_index_of_mem_nocase(haystack, haystack_len, needle, needle_len);

    // Use the result in some way to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
