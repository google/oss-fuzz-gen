#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming the definition of bstr is provided somewhere
typedef struct {
    size_t len;
    char *data;
} bstr;

// Function-under-test declaration
int bstr_cmp_c(const bstr *, const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a bstr and a C-string
    if (size < 2) {
        return 0;
    }

    // Create a bstr from the input data
    bstr bstr_input;
    bstr_input.len = size / 2;
    bstr_input.data = (char *)data;

    // Create a C-string from the remaining input data
    char *cstr_input = (char *)(data + bstr_input.len);
    size_t cstr_len = size - bstr_input.len;

    // Ensure the C-string is null-terminated
    char cstr_buffer[cstr_len + 1];
    memcpy(cstr_buffer, cstr_input, cstr_len);
    cstr_buffer[cstr_len] = '\0';

    // Call the function-under-test
    int result = bstr_cmp_c(&bstr_input, cstr_buffer);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
