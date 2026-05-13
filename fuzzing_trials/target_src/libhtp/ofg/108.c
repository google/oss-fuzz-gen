#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of bstr and bstr_dup_lower is available
typedef struct {
    size_t len;
    char *data;
} bstr;

bstr *bstr_dup_lower(const bstr *);

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the bstr structure
    bstr input;
    input.len = size;
    input.data = (char *)malloc(size + 1);

    if (input.data == NULL) {
        return 0;
    }

    // Copy the data into the bstr structure and null-terminate it
    memcpy(input.data, data, size);
    input.data[size] = '\0';

    // Call the function under test
    bstr *result = bstr_dup_lower(&input);

    // Free the allocated memory
    free(input.data);

    // If result is not NULL, free the result's data
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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
