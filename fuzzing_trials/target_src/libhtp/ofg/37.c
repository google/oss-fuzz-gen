#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming the definition of bstr is something like this:
typedef struct {
    size_t len;
    char *data;
} bstr;

// Function-under-test
int bstr_cmp_c(const bstr *b, const char *c);

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to form a meaningful test
    }

    // Create a bstr instance
    bstr b;
    b.len = size / 2;
    b.data = (char *)data;

    // Create a null-terminated string from the remaining data
    size_t str_len = size - b.len;
    char *c = (char *)(data + b.len);

    // Ensure null-termination
    if (str_len > 0) {
        c[str_len - 1] = '\0';
    }

    // Call the function-under-test
    int result = bstr_cmp_c(&b, c);

    // Return zero to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
