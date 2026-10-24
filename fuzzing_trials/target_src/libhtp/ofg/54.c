#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a struct defined somewhere in the codebase
typedef struct {
    char *data;
    size_t length;
} bstr;

// Function signature for the function-under-test
void bstr_adjust_size(bstr *str, size_t new_size);

// Fuzzing harness for bstr_adjust_size
int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize bstr
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Initialize bstr
    bstr test_bstr;
    test_bstr.length = size;
    test_bstr.data = (char *)malloc(size + 1);
    if (test_bstr.data == NULL) {
        return 0;
    }

    // Copy data into bstr's data
    memcpy(test_bstr.data, data, size);
    test_bstr.data[size] = '\0'; // Null-terminate the string

    // Extract a new size for the adjustment from the input data
    size_t new_size = *(size_t *)data;

    // Call the function-under-test
    bstr_adjust_size(&test_bstr, new_size);

    // Clean up
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
