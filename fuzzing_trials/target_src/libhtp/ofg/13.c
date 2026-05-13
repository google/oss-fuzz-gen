#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function-under-test declaration
int bstr_util_cmp_mem_nocasenorzero(const void *s1, size_t len1, const void *s2, size_t len2);

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the inputs to the function-under-test
    const void *s1;
    size_t len1;
    const void *s2;
    size_t len2;

    // Ensure the data is large enough to split into two non-empty parts
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts
    len1 = size / 2;
    len2 = size - len1;

    // Assign pointers to the respective parts of the input data
    s1 = (const void *)data;
    s2 = (const void *)(data + len1);

    // Call the function-under-test
    int result = bstr_util_cmp_mem_nocasenorzero(s1, len1, s2, len2);

    // Return 0 to indicate successful execution of the fuzzer
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
