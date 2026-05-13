#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a struct defined elsewhere
typedef struct {
    char *data;
    size_t len;
} bstr;

// Function-under-test declaration
char * bstr_util_strdup_to_c(const bstr *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a bstr object
    bstr input_bstr;
    input_bstr.data = (char *)malloc(size + 1);
    if (input_bstr.data == NULL) {
        return 0;
    }

    // Copy data to input_bstr and ensure null-termination
    memcpy(input_bstr.data, data, size);
    input_bstr.data[size] = '\0';
    input_bstr.len = size;

    // Call the function-under-test
    char *result = bstr_util_strdup_to_c(&input_bstr);

    // Free allocated memory
    free(input_bstr.data);
    free(result);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
