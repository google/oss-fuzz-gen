#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Assume the function is defined somewhere else
int bstr_util_mem_index_of_mem_nocase(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Split the input data into two parts for haystack and needle
    if (size < 2) {
        return 0; // Not enough data to split
    }

    // Calculate sizes for haystack and needle
    size_t haystack_len = size / 2;
    size_t needle_len = size - haystack_len;

    // Ensure non-zero length for both haystack and needle
    if (haystack_len == 0 || needle_len == 0) {
        return 0;
    }

    // Assign pointers to haystack and needle
    const void *haystack = (const void *)data;
    const void *needle = (const void *)(data + haystack_len);

    // Call the function-under-test
    int result = bstr_util_mem_index_of_mem_nocase(haystack, haystack_len, needle, needle_len);

    // Use the result to avoid compiler warnings about unused variables
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
