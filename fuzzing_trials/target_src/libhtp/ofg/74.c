#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include stdlib.h for malloc and free
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

// Remove the extern "C" linkage specification since this is a C file
int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to form two strings
    }

    // Split the data into two parts for bstr and char* inputs
    size_t bstr_size = size / 2;
    size_t char_size = size - bstr_size;

    // Create and initialize a bstr object
    bstr bstr_input;
    bstr_input.realptr = (unsigned char *)data; // Use realptr instead of data
    bstr_input.len = bstr_size;
    bstr_input.size = bstr_size; // Initialize size to match len

    // Create a null-terminated string for the char* input
    char *char_input = (char *)malloc(char_size + 1);
    if (char_input == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(char_input, data + bstr_size, char_size);
    char_input[char_size] = '\0';

    // Call the function-under-test
    int result = bstr_index_of_c(&bstr_input, char_input);

    // Clean up
    free(char_input);

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
