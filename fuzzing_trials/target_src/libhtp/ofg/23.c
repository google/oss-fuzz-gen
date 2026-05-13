#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Assuming bstr is a struct with a pointer to data and a length
typedef struct {
    const char *data;
    size_t len;
} bstr;

// Function under test
int bstr_begins_with_c(const bstr *b, const char *prefix);

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to create meaningful inputs
    }

    // Create a bstr instance
    bstr b;
    b.data = (const char *)data;
    b.len = size;

    // Create a prefix string from the data
    // Ensure null-termination by copying to a new buffer
    size_t prefix_len = size / 2; // Use half of the data for the prefix
    char *prefix = (char *)malloc(prefix_len + 1);
    if (prefix == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(prefix, data, prefix_len);
    prefix[prefix_len] = '\0'; // Null-terminate the prefix

    // Call the function under test
    int result = bstr_begins_with_c(&b, prefix);

    // Clean up
    free(prefix);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
