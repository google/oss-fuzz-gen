// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_hasattr at dwarf_query.c:871:1 in libdwarf.h
// dwarf_die_abbrev_children_flag at dwarf_query.c:1816:1 in libdwarf.h
// dwarf_cu_header_basics at dwarf_query.c:2157:1 in libdwarf.h
// dwarf_get_version_of_die at dwarf_query.c:2074:1 in libdwarf.h
// dwarf_attr at dwarf_query.c:896:1 in libdwarf.h
// dwarf_bitoffset at dwarf_query.c:1709:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Half)) {
        return 0;
    }

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Die die = 0;
    Dwarf_Bool returned_bool = 0;
    Dwarf_Attribute returned_attr = 0;
    Dwarf_Unsigned returned_offset = 0;
    Dwarf_Half attrnum = *(Dwarf_Half *)Data;
    Dwarf_Half version = 0;
    Dwarf_Half offset_size = 0;
    Dwarf_Bool has_child = 0;
    Dwarf_Bool is_info = 0;
    Dwarf_Bool is_dwo = 0;
    Dwarf_Half offset_size_cu = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 *signature = 0;
    Dwarf_Off offset_of_length = 0;
    Dwarf_Unsigned total_byte_length = 0;

    // Create a dummy Dwarf_Debug for fuzzing
    int res = dwarf_init_path("./dummy_file", 0, 0, DW_GROUPNUMBER_ANY, 0, 0, &dbg, &error);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Fuzz dwarf_hasattr
    dwarf_hasattr(die, attrnum, &returned_bool, &error);

    // Fuzz dwarf_die_abbrev_children_flag
    dwarf_die_abbrev_children_flag(die, &has_child);

    // Fuzz dwarf_cu_header_basics
    dwarf_cu_header_basics(die, &version, &is_info, &is_dwo, &offset_size_cu, 
                           &address_size, &extension_size, &signature, 
                           &offset_of_length, &total_byte_length, &error);

    // Fuzz dwarf_get_version_of_die
    dwarf_get_version_of_die(die, &version, &offset_size);

    // Fuzz dwarf_attr
    dwarf_attr(die, attrnum, &returned_attr, &error);

    // Fuzz dwarf_bitoffset
    dwarf_bitoffset(die, &attrnum, &returned_offset, &error);

    dwarf_finish(dbg);
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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    