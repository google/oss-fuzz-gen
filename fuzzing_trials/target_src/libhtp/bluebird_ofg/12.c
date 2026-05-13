#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libhtp/htp/bstr.h"  // Correct path for bstr.h

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Declare and initialize the bstr structure
    bstr b;
    
    // Ensure size is non-zero to avoid empty data
    if (size == 0) {
        return 0;
    }
    
    // Initialize the bstr structure
    b.realptr = (unsigned char *)data;  // Cast data to unsigned char* as bstr expects a pointer to unsigned char
    b.len = size;                       // Set the length of the bstr
    b.size = size;                      // Set the buffer size of the bstr

    // Choose a character to search for, using the first byte of the input data
    int search_char = data[0];

    // Call the function-under-test
    int result = bstr_rchr(&b, search_char);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
