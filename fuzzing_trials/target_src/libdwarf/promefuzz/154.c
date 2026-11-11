// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_machine_architecture at dwarf_query.c:2284:1 in libdwarf.h
// dwarf_get_section_max_offsets_d at dwarf_init_finish.c:1655:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"

static void initialize_dummy_debug(Dwarf_Debug *dw_dbg) {
    // Initialize a dummy Dwarf_Debug object
    *dw_dbg = NULL;
}

int LLVMFuzzerTestOneInput_154(const uint8_t *Data, size_t Size) {
    Dwarf_Debug dw_dbg;
    initialize_dummy_debug(&dw_dbg);

    // Prepare output variables for dwarf_machine_architecture
    Dwarf_Small dw_ftype = 0;
    Dwarf_Small dw_obj_pointersize = 0;
    Dwarf_Bool dw_obj_is_big_endian = 0;
    Dwarf_Unsigned dw_obj_machine = 0;
    Dwarf_Unsigned dw_obj_flags = 0;
    Dwarf_Small dw_path_source = 0;
    Dwarf_Unsigned dw_ub_offset = 0;
    Dwarf_Unsigned dw_ub_count = 0;
    Dwarf_Unsigned dw_ub_index = 0;
    Dwarf_Unsigned dw_comdat_groupnumber = 0;

    // Call the target function
    dwarf_machine_architecture(dw_dbg, &dw_ftype, &dw_obj_pointersize,
                               &dw_obj_is_big_endian, &dw_obj_machine,
                               &dw_obj_flags, &dw_path_source, &dw_ub_offset,
                               &dw_ub_count, &dw_ub_index, &dw_comdat_groupnumber);

    // Prepare output variables for dwarf_get_section_max_offsets_d
    Dwarf_Unsigned dw_debug_info_size = 0;
    Dwarf_Unsigned dw_debug_abbrev_size = 0;
    Dwarf_Unsigned dw_debug_line_size = 0;
    Dwarf_Unsigned dw_debug_loc_size = 0;
    Dwarf_Unsigned dw_debug_aranges_size = 0;
    Dwarf_Unsigned dw_debug_macinfo_size = 0;
    Dwarf_Unsigned dw_debug_pubnames_size = 0;
    Dwarf_Unsigned dw_debug_str_size = 0;
    Dwarf_Unsigned dw_debug_frame_size = 0;
    Dwarf_Unsigned dw_debug_ranges_size = 0;
    Dwarf_Unsigned dw_debug_pubtypes_size = 0;
    Dwarf_Unsigned dw_debug_types_size = 0;
    Dwarf_Unsigned dw_debug_macro_size = 0;
    Dwarf_Unsigned dw_debug_str_offsets_size = 0;
    Dwarf_Unsigned dw_debug_sup_size = 0;
    Dwarf_Unsigned dw_debug_cu_index_size = 0;
    Dwarf_Unsigned dw_debug_tu_index_size = 0;
    Dwarf_Unsigned dw_debug_names_size = 0;
    Dwarf_Unsigned dw_debug_loclists_size = 0;
    Dwarf_Unsigned dw_debug_rnglists_size = 0;

    // Call the second target function
    dwarf_get_section_max_offsets_d(dw_dbg, &dw_debug_info_size, &dw_debug_abbrev_size,
                                    &dw_debug_line_size, &dw_debug_loc_size, &dw_debug_aranges_size,
                                    &dw_debug_macinfo_size, &dw_debug_pubnames_size, &dw_debug_str_size,
                                    &dw_debug_frame_size, &dw_debug_ranges_size, &dw_debug_pubtypes_size,
                                    &dw_debug_types_size, &dw_debug_macro_size, &dw_debug_str_offsets_size,
                                    &dw_debug_sup_size, &dw_debug_cu_index_size, &dw_debug_tu_index_size,
                                    &dw_debug_names_size, &dw_debug_loclists_size, &dw_debug_rnglists_size);

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

        LLVMFuzzerTestOneInput_154(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    