// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_discr_list at dwarf_dsc.c:165:5 in libdwarf.h
// dwarf_discr_entry_u at dwarf_dsc.c:239:1 in libdwarf.h
// dwarf_discr_entry_s at dwarf_dsc.c:283:1 in libdwarf.h
// dwarf_cu_header_basics at dwarf_query.c:2157:1 in libdwarf.h
// dwarf_CU_dieoffset_given_die at dwarf_global.c:1653:1 in libdwarf.h
// dwarf_get_macro_context at dwarf_macro5.c:1558:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Error error = NULL;
    Dwarf_Unsigned entrynum = Data[0];
    Dwarf_Half out_type;
    Dwarf_Unsigned out_discr_low, out_discr_high;
    Dwarf_Signed out_discr_low_s, out_discr_high_s;

    // Initialize the necessary libdwarf structures
    Dwarf_Debug debug = NULL;
    Dwarf_Die die = NULL;
    Dwarf_Dsc_Head dsc_head = NULL;
    Dwarf_Unsigned dsc_array_length_out;

    // Ensure dsc_head is properly initialized
    if (dwarf_discr_list(debug, (Dwarf_Small *)Data, Size, &dsc_head, &dsc_array_length_out, &error) != DW_DLV_OK) {
        return 0; // If initialization fails, exit early
    }

    // Fuzzing dwarf_discr_entry_u
    dwarf_discr_entry_u(dsc_head, entrynum, &out_type, &out_discr_low, &out_discr_high, &error);

    // Fuzzing dwarf_discr_entry_s
    dwarf_discr_entry_s(dsc_head, entrynum, &out_type, &out_discr_low_s, &out_discr_high_s, &error);

    // Fuzzing dwarf_cu_header_basics
    Dwarf_Half version;
    Dwarf_Bool is_info, is_dwo;
    Dwarf_Half offset_size, address_size, extension_size;
    Dwarf_Sig8 *signature;
    Dwarf_Off offset_of_length;
    Dwarf_Unsigned total_byte_length;
    dwarf_cu_header_basics(die, &version, &is_info, &is_dwo, &offset_size, &address_size, &extension_size, &signature, &offset_of_length, &total_byte_length, &error);

    // Fuzzing dwarf_CU_dieoffset_given_die
    Dwarf_Off return_offset;
    dwarf_CU_dieoffset_given_die(die, &return_offset, &error);

    // Fuzzing dwarf_get_macro_context
    Dwarf_Unsigned version_out, macro_unit_offset_out, macro_ops_count_out, macro_ops_data_length_out;
    Dwarf_Macro_Context macro_context;
    dwarf_get_macro_context(die, &version_out, &macro_context, &macro_unit_offset_out, &macro_ops_count_out, &macro_ops_data_length_out, &error);

    // Clean up
    if (dsc_head) {
        dwarf_dealloc(debug, dsc_head, DW_DLA_DSC_HEAD);
    }

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

        LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    