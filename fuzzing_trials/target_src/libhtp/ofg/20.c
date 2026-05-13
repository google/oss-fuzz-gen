#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Function-under-test declaration
int bstr_util_mem_index_of_mem_nocasenorzero(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to split into two parts
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for haystack and needle
    size_t haystack_len = size / 2;
    size_t needle_len = size - haystack_len;

    // Allocate memory for haystack and needle
    void *haystack = malloc(haystack_len);
    void *needle = malloc(needle_len);

    // Copy data into haystack and needle
    memcpy(haystack, data, haystack_len);
    memcpy(needle, data + haystack_len, needle_len);

    // Call the function-under-test
    int result = bstr_util_mem_index_of_mem_nocasenorzero(haystack, haystack_len, needle, needle_len);

    // Free allocated memory
    free(haystack);
    free(needle);

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
