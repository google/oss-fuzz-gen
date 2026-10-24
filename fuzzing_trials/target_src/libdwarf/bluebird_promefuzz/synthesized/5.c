#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file(Data, Size);

    Dwarf_Debug dw_dbg = NULL;
    Dwarf_Error dw_error = NULL;
    Dwarf_Fde dw_fde = NULL;
    Dwarf_Cie *dw_cie_data = NULL;
    Dwarf_Fde *dw_fde_data = NULL;
    Dwarf_Signed dw_cie_element_count = 0;
    Dwarf_Signed dw_fde_element_count = 0;
    Dwarf_Off dw_fde_off = 0;
    Dwarf_Off dw_cie_off = 0;
    Dwarf_Signed dw_offset_into_exception_tables = 0;
    Dwarf_Cie dw_cie_returned = NULL;

    // Initialize Dwarf_Debug
    int res = dwarf_init_path("./dummy_file", NULL, 0, 0, NULL, NULL, &dw_dbg, &dw_error);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Fuzz dwarf_get_fde_list
    res = dwarf_get_fde_list(dw_dbg, &dw_cie_data, &dw_cie_element_count, &dw_fde_data, &dw_fde_element_count, &dw_error);
    if (res == DW_DLV_OK) {
        // Fuzz dwarf_get_fde_exception_info
        for (Dwarf_Signed i = 0; i < dw_fde_element_count; ++i) {
            res = dwarf_get_fde_exception_info(dw_fde_data[i], &dw_offset_into_exception_tables, &dw_error);
        }

        // Fuzz dwarf_get_cie_of_fde
        for (Dwarf_Signed i = 0; i < dw_fde_element_count; ++i) {
            res = dwarf_get_cie_of_fde(dw_fde_data[i], &dw_cie_returned, &dw_error);
        }

        // Fuzz dwarf_fde_section_offset
        for (Dwarf_Signed i = 0; i < dw_fde_element_count; ++i) {
            res = dwarf_fde_section_offset(dw_dbg, dw_fde_data[i], &dw_fde_off, &dw_cie_off, &dw_error);
        }

        // Fuzz dwarf_get_fde_n
        for (Dwarf_Unsigned i = 0; i < dw_fde_element_count; ++i) {
            res = dwarf_get_fde_n(dw_fde_data, i, &dw_fde, &dw_error);
        }
    }

    // Fuzz dwarf_get_fde_list_eh
    res = dwarf_get_fde_list_eh(dw_dbg, &dw_cie_data, &dw_cie_element_count, &dw_fde_data, &dw_fde_element_count, &dw_error);

    // Cleanup
    dwarf_dealloc(dw_dbg, dw_cie_data, DW_DLA_LIST);
    dwarf_dealloc(dw_dbg, dw_fde_data, DW_DLA_LIST);
    dwarf_finish(dw_dbg);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
