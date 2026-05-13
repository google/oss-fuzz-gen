#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf.h> // Ensure the correct header for Dwarf_Signed and Dwarf_Unsigned is included

// Function signature for the function-under-test
DW_API int dwarf_decode_signed_leb128(char *dw_leb, Dwarf_Unsigned *dw_length, Dwarf_Signed *dw_value, char *dw_endptr);

int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Return early if there's no data to process
    }

    // Allocate memory for the input buffer and ensure it's null-terminated
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Initialize variables for the function call
    Dwarf_Unsigned length = 0;
    Dwarf_Signed value = 0;
    char endptr = '\0';  // Change endptr to a char instead of a char*

    // Call the function-under-test
    dwarf_decode_signed_leb128(input_data, &length, &value, &endptr);

    // Free allocated memory
    free(input_data);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_169(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
