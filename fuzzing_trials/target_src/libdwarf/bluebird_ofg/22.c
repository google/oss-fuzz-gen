#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Declare and initialize all variables
    Dwarf_Loc_Head_c loc_head = NULL;
    Dwarf_Unsigned index = 0;
    Dwarf_Small lle_value = 0;
    Dwarf_Unsigned rawval1 = 0;
    Dwarf_Unsigned rawval2 = 0;
    Dwarf_Bool debug_addr_unavailable = 0;
    Dwarf_Addr lopc = 0;
    Dwarf_Addr hipc = 0;
    Dwarf_Unsigned loclist_offset = 0;
    Dwarf_Locdesc_c locentry = NULL;
    Dwarf_Small lle_value_out = 0;
    Dwarf_Unsigned lle_offset = 0;
    Dwarf_Unsigned lle_length = 0;
    Dwarf_Error error = NULL;

    // Check if the size is sufficient for creating a Dwarf_Loc_Head_c object
    if (size >= sizeof(Dwarf_Loc_Head_c)) {
        loc_head = (Dwarf_Loc_Head_c)data;  // Cast data to Dwarf_Loc_Head_c if size is sufficient
    }

    // Call the function-under-test
    int result = dwarf_get_locdesc_entry_d(
        loc_head,
        index,
        &lle_value,
        &rawval1,
        &rawval2,
        &debug_addr_unavailable,
        &lopc,
        &hipc,
        &loclist_offset,
        &locentry,
        &lle_value_out,
        &lle_offset,
        &lle_length,
        &error
    );

    // Return 0 as required by the fuzzer
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
