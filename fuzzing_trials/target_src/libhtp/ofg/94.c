#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the bstr structure is defined as follows:
typedef struct {
    char *data;
    size_t length;
} bstr;

// Function-under-test
bstr *bstr_dup_ex(const bstr *str, size_t start, size_t len);

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid bstr
    if (size < sizeof(bstr)) {
        return 0;
    }

    // Create a bstr instance
    bstr input_bstr;
    input_bstr.length = size;
    input_bstr.data = (char *)malloc(size);
    if (input_bstr.data == NULL) {
        return 0;
    }
    memcpy(input_bstr.data, data, size);

    // Define start and len for bstr_dup_ex
    size_t start = 0;
    size_t len = size;

    // Call the function-under-test
    bstr *result = bstr_dup_ex(&input_bstr, start, len);

    // Clean up
    if (result != NULL) {
        free(result->data);
        free(result);
    }
    free(input_bstr.data);

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

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
