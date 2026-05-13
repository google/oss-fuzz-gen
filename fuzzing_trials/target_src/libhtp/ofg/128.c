#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is defined as follows:
typedef struct {
    char *data;
    size_t length;
} bstr;

// Function signature to be fuzzed
int bstr_chr(const bstr *str, int ch);

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for bstr and initialize it
    bstr test_bstr;
    test_bstr.data = (char *)malloc(size);
    if (test_bstr.data == NULL) {
        return 0;
    }

    // Copy the input data into the bstr data
    memcpy(test_bstr.data, data, size);
    test_bstr.length = size;

    // Use the first byte of data as the character to search for
    int ch = data[0];

    // Call the function-under-test
    bstr_chr(&test_bstr, ch);

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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
