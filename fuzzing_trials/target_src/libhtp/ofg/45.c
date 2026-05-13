#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the bstr structure is defined as follows
typedef struct {
    size_t len;
    char *data;
} bstr;

// Mock implementation of the function-under-test
static bstr *bstr_dup_mem(const void *src, size_t len) {
    if (src == NULL || len == 0) {
        return NULL;
    }

    bstr *new_bstr = (bstr *)malloc(sizeof(bstr));
    if (new_bstr == NULL) {
        return NULL;
    }

    new_bstr->data = (char *)malloc(len);
    if (new_bstr->data == NULL) {
        free(new_bstr);
        return NULL;
    }

    memcpy(new_bstr->data, src, len);
    new_bstr->len = len;

    return new_bstr;
}

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Ensure that the input data is not null and has a valid size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    bstr *result = bstr_dup_mem((const void *)data, size);

    // Check if the result is not NULL and validate its contents
    if (result != NULL) {
        // Verify that the length matches
        if (result->len != size) {
            abort(); // Trigger a failure if lengths do not match
        }

        // Verify that the data matches
        if (memcmp(result->data, data, size) != 0) {
            abort(); // Trigger a failure if data does not match
        }

        // Clean up
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
