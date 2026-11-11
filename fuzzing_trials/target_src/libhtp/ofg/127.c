#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Define and initialize the `bstr` structure
    bstr input_bstr;
    input_bstr.realptr = (unsigned char *)data; // Cast data to unsigned char pointer
    input_bstr.len = size;                      // Set the length of the bstr
    input_bstr.size = size;                     // Set the size of the bstr buffer

    // Define an integer value to search for in the bstr
    int search_char = 'a'; // Example character to search for

    // Call the function-under-test
    int result = bstr_chr(&input_bstr, search_char);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
