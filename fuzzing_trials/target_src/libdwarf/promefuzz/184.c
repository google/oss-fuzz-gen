// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_fde_list at dwarf_frame.c:424:1 in libdwarf.h
// dwarf_dealloc_fde_cie_list at dwarf_frame2.c:2045:1 in libdwarf.h
// dwarf_get_cie_of_fde at dwarf_frame.c:349:1 in libdwarf.h
// dwarf_fde_section_offset at dwarf_frame.c:1524:1 in libdwarf.h
// dwarf_get_fde_list_eh at dwarf_frame.c:389:1 in libdwarf.h
// dwarf_dealloc_fde_cie_list at dwarf_frame2.c:2045:1 in libdwarf.h
// dwarf_get_fde_n at dwarf_frame.c:1249:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_184(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Debug dbg = 0; // Assume a valid Dwarf_Debug is initialized elsewhere
    Dwarf_Error error = 0;
    Dwarf_Cie *cie_data = 0;
    Dwarf_Signed cie_count = 0;
    Dwarf_Fde *fde_data = 0;
    Dwarf_Signed fde_count = 0;

    int res = dwarf_get_fde_list(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &error);
    if (res == DW_DLV_OK) {
        dwarf_dealloc_fde_cie_list(dbg, cie_data, cie_count, fde_data, fde_count);
    }

    Dwarf_Fde fde = 0; // Assume a valid Dwarf_Fde is initialized elsewhere
    Dwarf_Cie cie_returned = 0;
    res = dwarf_get_cie_of_fde(fde, &cie_returned, &error);

    Dwarf_Off fde_off = 0;
    Dwarf_Off cie_off = 0;
    res = dwarf_fde_section_offset(dbg, fde, &fde_off, &cie_off, &error);

    res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &error);
    if (res == DW_DLV_OK) {
        dwarf_dealloc_fde_cie_list(dbg, cie_data, cie_count, fde_data, fde_count);
    }

    Dwarf_Fde returned_fde = 0;
    res = dwarf_get_fde_n(fde_data, 0, &returned_fde, &error);

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

        LLVMFuzzerTestOneInput_184(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    