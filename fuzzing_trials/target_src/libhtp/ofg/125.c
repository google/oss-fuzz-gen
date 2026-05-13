#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // Include for malloc and free

// Assuming bstr is a structure defined as follows:
typedef struct {
    char *data;
    size_t len;
} bstr;

// Function-under-test declaration
int bstr_begins_with_c_nocase(const bstr *b, const char *prefix);

// Helper function to create a bstr from data
bstr create_bstr_125(const uint8_t *data, size_t size) {
    bstr str;
    str.data = (char *)data;
    str.len = size;
    return str;
}

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    if (size < 2) return 0;  // Ensure there's enough data for meaningful input

    // Split the data into two parts: one for bstr and one for prefix
    size_t bstr_size = size / 2;
    size_t prefix_size = size - bstr_size;

    bstr b = create_bstr_125(data, bstr_size);
    const char *prefix = (const char *)(data + bstr_size);

    // Ensure the prefix is null-terminated
    char *null_terminated_prefix = (char *)malloc(prefix_size + 1);
    if (!null_terminated_prefix) return 0;  // Handle memory allocation failure
    memcpy(null_terminated_prefix, prefix, prefix_size);
    null_terminated_prefix[prefix_size] = '\0';

    // Call the function-under-test
    int result = bstr_begins_with_c_nocase(&b, null_terminated_prefix);

    // Clean up
    free(null_terminated_prefix);

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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
