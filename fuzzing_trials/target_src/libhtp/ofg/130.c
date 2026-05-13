#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of bstr and bstr_dup is available
typedef struct {
    size_t len;
    char *data;
} bstr;

bstr *bstr_dup(const bstr *str);

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Create a bstr object from the input data
    bstr input_str;
    input_str.len = size;
    input_str.data = (char *)malloc(size + 1);
    if (input_str.data == NULL) {
        return 0; // Exit if memory allocation fails
    }

    memcpy(input_str.data, data, size);
    input_str.data[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    bstr *duplicated_str = bstr_dup(&input_str);

    // Clean up
    if (duplicated_str != NULL) {
        free(duplicated_str->data);
        free(duplicated_str);
    }
    free(input_str.data);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
