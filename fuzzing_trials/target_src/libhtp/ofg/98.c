#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Assuming the definition of bstr and bstr_dup_c is provided in some header file
typedef struct {
    char *data;
    size_t length;
} bstr;

bstr *bstr_dup_c(const char *input);

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Allocate memory for a null-terminated string
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the data into the input buffer and null-terminate it
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    bstr *result = bstr_dup_c(input);

    // Free the result if it is not NULL
    if (result != NULL) {
        free(result->data);
        free(result);
    }

    // Free the input buffer
    free(input);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
