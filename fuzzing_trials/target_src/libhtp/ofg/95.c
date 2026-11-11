#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of bstr and bstr_dup_ex is available
typedef struct {
    size_t len;
    char *data;
} bstr;

bstr *bstr_dup_ex(const bstr *str, size_t start, size_t len);

// Fuzzer test function
int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    if (size < sizeof(bstr)) {
        return 0; // Not enough data to form a valid bstr
    }

    // Initialize a bstr from the input data
    bstr input_bstr;
    input_bstr.len = size - sizeof(bstr);
    input_bstr.data = (char *)malloc(input_bstr.len + 1);
    if (input_bstr.data == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(input_bstr.data, data + sizeof(bstr), input_bstr.len);
    input_bstr.data[input_bstr.len] = '\0'; // Null-terminate

    // Define start and len for bstr_dup_ex
    size_t start = 0;
    size_t len = input_bstr.len;

    // Call the function-under-test
    bstr *result = bstr_dup_ex(&input_bstr, start, len);

    // Free allocated memory
    free(input_bstr.data);
    if (result != NULL) {
        free(result->data);
        free(result);
    }

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
