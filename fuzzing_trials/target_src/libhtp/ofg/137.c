#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function-under-test declaration
int bstr_util_mem_index_of_c(const void *haystack, size_t haystack_len, const char *needle);

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    // Ensure that the input data is non-null and has a minimum size
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts: haystack and needle
    size_t needle_len = 1; // At least one character for the needle
    size_t haystack_len = size - needle_len;

    const void *haystack = (const void *)data;
    const char *needle = (const char *)(data + haystack_len);

    // Ensure that the needle is null-terminated
    char needle_buffer[2];
    needle_buffer[0] = *needle;
    needle_buffer[1] = '\0';

    // Call the function-under-test
    int result = bstr_util_mem_index_of_c(haystack, haystack_len, needle_buffer);

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

    LLVMFuzzerTestOneInput_137(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
