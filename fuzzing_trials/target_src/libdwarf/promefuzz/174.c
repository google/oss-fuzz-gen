// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dealloc_fde_cie_list at dwarf_frame2.c:2045:1 in libdwarf.h
// dwarf_get_cie_of_fde at dwarf_frame.c:349:1 in libdwarf.h
// dwarf_get_fde_list at dwarf_frame.c:424:1 in libdwarf.h
// dwarf_fde_section_offset at dwarf_frame.c:1524:1 in libdwarf.h
// dwarf_get_fde_list_eh at dwarf_frame.c:389:1 in libdwarf.h
// dwarf_get_fde_n at dwarf_frame.c:1249:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void write_dummy_file(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_174(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Fde) + sizeof(Dwarf_Cie)) {
        return 0;
    }

    Dwarf_Debug dw_dbg = 0; // Assume a valid Dwarf_Debug is obtained from elsewhere
    Dwarf_Cie *dw_cie_data = NULL;
    Dwarf_Fde *dw_fde_data = NULL;
    Dwarf_Signed dw_cie_element_count = 0;
    Dwarf_Signed dw_fde_element_count = 0;
    Dwarf_Error dw_error = NULL;

    // Allocate memory for CIE and FDE arrays
    if (Size > 0) {
        dw_cie_element_count = Size / sizeof(Dwarf_Cie);
        dw_fde_element_count = Size / sizeof(Dwarf_Fde);
        
        dw_cie_data = (Dwarf_Cie *)malloc(dw_cie_element_count * sizeof(Dwarf_Cie));
        dw_fde_data = (Dwarf_Fde *)malloc(dw_fde_element_count * sizeof(Dwarf_Fde));

        if (dw_cie_data) {
            memset(dw_cie_data, 0, dw_cie_element_count * sizeof(Dwarf_Cie));
        }
        if (dw_fde_data) {
            memset(dw_fde_data, 0, dw_fde_element_count * sizeof(Dwarf_Fde));
        }
    }

    // Fuzz dwarf_dealloc_fde_cie_list
    dwarf_dealloc_fde_cie_list(dw_dbg, dw_cie_data, dw_cie_element_count, dw_fde_data, dw_fde_element_count);

    // Fuzz dwarf_get_cie_of_fde
    Dwarf_Cie dw_cie_returned;
    if (dw_fde_data && dw_fde_element_count > 0) {
        dwarf_get_cie_of_fde(dw_fde_data[0], &dw_cie_returned, &dw_error);
    }

    // Fuzz dwarf_get_fde_list
    Dwarf_Cie *cie_data = NULL;
    Dwarf_Fde *fde_data = NULL;
    Dwarf_Signed cie_count = 0;
    Dwarf_Signed fde_count = 0;
    dwarf_get_fde_list(dw_dbg, &cie_data, &cie_count, &fde_data, &fde_count, &dw_error);

    // Fuzz dwarf_fde_section_offset
    Dwarf_Off dw_fde_off, dw_cie_off;
    if (dw_fde_data && dw_fde_element_count > 0) {
        dwarf_fde_section_offset(dw_dbg, dw_fde_data[0], &dw_fde_off, &dw_cie_off, &dw_error);
    }

    // Fuzz dwarf_get_fde_list_eh
    Dwarf_Cie *cie_data_eh = NULL;
    Dwarf_Fde *fde_data_eh = NULL;
    Dwarf_Signed cie_count_eh = 0;
    Dwarf_Signed fde_count_eh = 0;
    dwarf_get_fde_list_eh(dw_dbg, &cie_data_eh, &cie_count_eh, &fde_data_eh, &fde_count_eh, &dw_error);

    // Fuzz dwarf_get_fde_n
    Dwarf_Fde dw_returned_fde;
    Dwarf_Unsigned dw_fde_index = Size % 10;
    if (dw_fde_data && dw_fde_element_count > 0) {
        dwarf_get_fde_n(dw_fde_data, dw_fde_index % dw_fde_element_count, &dw_returned_fde, &dw_error);
    }

    // Free allocated memory
    free(dw_cie_data);
    free(dw_fde_data);

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

        LLVMFuzzerTestOneInput_174(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    