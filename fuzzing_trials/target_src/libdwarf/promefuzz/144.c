// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_arange_cu_header_offset at dwarf_arange.c:650:1 in libdwarf.h
// dwarf_get_arange_info_b at dwarf_arange.c:691:1 in libdwarf.h
// dwarf_get_fde_range at dwarf_frame.c:640:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size) {
    Dwarf_Arange arange = NULL;
    Dwarf_Fde fde = NULL;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Off cu_header_offset = 0;
    Dwarf_Unsigned segment;
    Dwarf_Unsigned segment_entry_size;
    Dwarf_Addr start;
    Dwarf_Unsigned length;
    Dwarf_Off cu_die_offset;
    Dwarf_Addr low_pc;
    Dwarf_Unsigned func_length;
    Dwarf_Small *fde_bytes;
    Dwarf_Unsigned fde_byte_length;
    Dwarf_Off cie_offset;
    Dwarf_Signed cie_index;
    Dwarf_Off fde_offset;

    // Attempt to call the target functions with NULL pointers
    dwarf_get_arange_cu_header_offset(arange, &cu_header_offset, &error);
    dwarf_get_arange_info_b(arange, &segment, &segment_entry_size, &start, &length, &cu_die_offset, &error);
    dwarf_get_fde_range(fde, &low_pc, &func_length, &fde_bytes, &fde_byte_length, &cie_offset, &cie_index, &fde_offset, &error);
    
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

        LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    