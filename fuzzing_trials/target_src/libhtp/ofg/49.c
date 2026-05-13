#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

// Remove the 'extern "C"' as it is not valid in C, it's used in C++ for linkage specification
int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2) return 0;

    // Split the input data into two parts for bstr and char*
    size_t bstr_len = size / 2;
    size_t char_len = size - bstr_len;

    // Create and initialize a bstr object
    bstr bstr_obj;
    bstr_obj.len = bstr_len;
    bstr_obj.size = bstr_len;
    bstr_obj.realptr = (unsigned char *)data;  // Use the first half of the data

    // Create and initialize a null-terminated string for the second parameter
    char *char_str = (char *)(data + bstr_len);

    // Ensure null-termination, only if char_len is greater than 0
    if (char_len > 0) {
        char_str[char_len - 1] = '\0';
    }

    // Call the function-under-test
    int result = bstr_index_of_c_nocase(&bstr_obj, char_str);

    // Return 0 as required by LLVMFuzzerTestOneInput
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
