#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern int bstr_util_mem_index_of_mem_nocasenorzero(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure there is enough data to split into two non-empty parts
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts
    size_t split_point = size / 2;

    // The first part is the haystack
    const void *haystack = data;
    size_t haystack_len = split_point;

    // The second part is the needle
    const void *needle = data + split_point;
    size_t needle_len = size - split_point;

    // Call the function under test
    int result = bstr_util_mem_index_of_mem_nocasenorzero(haystack, haystack_len, needle, needle_len);

    // Use the result to avoid any compiler optimizations that might remove the call
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
