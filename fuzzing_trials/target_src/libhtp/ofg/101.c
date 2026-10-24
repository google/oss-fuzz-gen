#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function prototype for the function-under-test
int bstr_util_mem_index_of_c_nocase(const void *mem, size_t mem_size, const char *str);

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure that 'size' is large enough to have meaningful input for both 'mem' and 'str'
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts: 'mem' and 'str'
    size_t mem_size = size / 2;
    const void *mem = (const void *)data;
    const char *str = (const char *)(data + mem_size);

    // Ensure 'str' is null-terminated
    char *mutable_str = (char *)malloc(size - mem_size + 1);
    if (mutable_str == NULL) {
        return 0;
    }
    memcpy(mutable_str, str, size - mem_size);
    mutable_str[size - mem_size] = '\0';

    // Call the function-under-test
    int result = bstr_util_mem_index_of_c_nocase(mem, mem_size, mutable_str);

    // Clean up
    free(mutable_str);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
