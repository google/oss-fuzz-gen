#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of bstr is available
typedef struct {
    char *data;
    size_t length;
} bstr;

// Function-under-test
int bstr_char_at(const bstr *str, size_t index);

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Initialize bstr structure
    bstr test_bstr;
    test_bstr.length = size;
    test_bstr.data = (char *)malloc(size + 1); // +1 for null termination

    if (test_bstr.data == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy data to bstr's data field
    memcpy(test_bstr.data, data, size);
    test_bstr.data[size] = '\0'; // Null-terminate the string

    // Fuzzing the bstr_char_at function
    if (size > 0) {
        // Call the function with all possible indices
        for (size_t i = 0; i < size; i++) {
            bstr_char_at(&test_bstr, i);
        }
    }

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
