#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a structure defined somewhere in the library
typedef struct {
    size_t len;
    char *data;
} bstr;

// Function prototype for the function-under-test
bstr *bstr_to_lowercase(bstr *str);

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Allocate memory for bstr structure
    bstr input_str;
    input_str.len = size;
    input_str.data = (char *)malloc(size + 1);

    // Ensure the input data is not NULL
    if (input_str.data == NULL) {
        return 0;
    }

    // Copy the fuzzing data into the bstr structure
    memcpy(input_str.data, data, size);
    input_str.data[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    bstr *result = bstr_to_lowercase(&input_str);

    // Free allocated memory for input string
    free(input_str.data);

    // If the result is not NULL, free the result as well
    if (result != NULL && result != &input_str) {
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
