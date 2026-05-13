#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a structure similar to this:
typedef struct {
    char *data;
    size_t len;
} bstr;

// Function signature to be fuzzed
int bstr_rchr(const bstr *str, int ch);

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Need at least 1 byte to proceed
    }

    // Create a bstr object
    bstr test_bstr;
    test_bstr.len = size;
    test_bstr.data = (char *)malloc(size + 1); // Allocate memory for data
    if (test_bstr.data == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the input data to the bstr data and null-terminate it
    memcpy(test_bstr.data, data, size);
    test_bstr.data[size] = '\0';

    // Use the first byte of data as the character to search for
    int ch = (int)data[0];

    // Call the function-under-test
    bstr_rchr(&test_bstr, ch);

    // Free allocated memory
    free(test_bstr.data);

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
