#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a structure defined somewhere in the codebase
typedef struct {
    char *data;
    size_t length;
} bstr;

// To avoid multiple definition error, we will make this function static
static bstr* bstr_expand(bstr *str, size_t new_size) {
    if (str == NULL || new_size <= str->length) {
        return str;
    }
    char *new_data = (char *)realloc(str->data, new_size);
    if (new_data == NULL) {
        return NULL;
    }
    str->data = new_data;
    str->length = new_size;
    return str;
}

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Initialize bstr structure
    bstr str;
    str.length = size;
    str.data = (char *)malloc(size);
    if (str.data == NULL) {
        return 0;
    }

    // Copy data into bstr
    memcpy(str.data, data, size);

    // Extract new_size from the input data
    size_t new_size = *((size_t *)data);

    // Call the function under test
    bstr *result = bstr_expand(&str, new_size);

    // Clean up
    free(str.data);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
