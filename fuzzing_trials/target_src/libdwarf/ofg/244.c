#include <stdint.h>
#include <stddef.h>
#include <dwarf.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    Dwarf_Line line = (Dwarf_Line)data;  // Casting data to Dwarf_Line
    Dwarf_Unsigned srcfileno = 0;        // Initialize Dwarf_Unsigned
    Dwarf_Error error = NULL;            // Initialize Dwarf_Error

    // Ensure that size is non-zero to avoid passing NULL to the function
    if (size == 0) {
        return 0;
    }

    // Call the function under test
    int result = dwarf_line_srcfileno(line, &srcfileno, &error);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_244(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
