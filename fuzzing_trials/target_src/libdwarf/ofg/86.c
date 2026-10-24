#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <dwarf.h> // Include this for Dwarf_Error and other related types

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg = 0; // Assuming a valid Dwarf_Debug object is initialized elsewhere
    Dwarf_Small *small_data = (Dwarf_Small *)data;
    Dwarf_Unsigned unsigned_data = size;
    Dwarf_Dsc_Head *dsc_head = NULL;
    Dwarf_Unsigned *ret_unsigned = NULL;
    Dwarf_Error error = 0;

    // Call the function-under-test
    dwarf_discr_list(dbg, small_data, unsigned_data, dsc_head, ret_unsigned, &error);

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

    LLVMFuzzerTestOneInput_86(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
