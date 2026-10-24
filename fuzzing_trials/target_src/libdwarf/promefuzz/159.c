// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_next_cu_header_d at dwarf_die_deliv.c:1088:1 in libdwarf.h
// dwarf_siblingof_b at dwarf_die_deliv.c:2749:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_get_debugfission_for_die at dwarf_die_deliv.c:256:1 in libdwarf.h
// dwarf_siblingof_c at dwarf_die_deliv.c:2782:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_hasattr at dwarf_query.c:871:1 in libdwarf.h
// dwarf_tag at dwarf_query.c:210:1 in libdwarf.h
// dwarf_die_text at dwarf_query.c:834:1 in libdwarf.h
// dwarf_bitoffset at dwarf_query.c:1709:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_159(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Half)) {
        return 0;
    }

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Die die = 0;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Half header_cu_type = 0;

    // Initialize Dwarf_Debug
    if (dwarf_init_path("./dummy_file", 0, 0, DW_GROUPNUMBER_ANY, 0, 0, &dbg, &error) != DW_DLV_OK) {
        return 0;
    }

    // Attempt to get the first DIE
    if (dwarf_next_cu_header_d(dbg, 1, &cu_header_length, &version_stamp, &abbrev_offset,
                               &address_size, 0, &next_cu_header, &header_cu_type, 0, 0, 0, &error) == DW_DLV_OK) {
        if (dwarf_siblingof_b(dbg, 0, 1, &die, &error) != DW_DLV_OK) {
            dwarf_finish(dbg);
            return 0;
        }
    }

    // Fuzz dwarf_get_debugfission_for_die
    struct Dwarf_Debug_Fission_Per_CU_s fission_per_cu;
    memset(&fission_per_cu, 0, sizeof(fission_per_cu));
    dwarf_get_debugfission_for_die(die, &fission_per_cu, &error);

    // Fuzz dwarf_siblingof_c
    Dwarf_Die sibling_die = 0;
    dwarf_siblingof_c(die, &sibling_die, &error);
    if (sibling_die) {
        dwarf_dealloc(dbg, sibling_die, DW_DLA_DIE);
    }

    // Fuzz dwarf_hasattr
    Dwarf_Half attrnum;
    memcpy(&attrnum, Data, sizeof(Dwarf_Half));
    Dwarf_Bool has_attr = 0;
    dwarf_hasattr(die, attrnum, &has_attr, &error);

    // Fuzz dwarf_tag
    Dwarf_Half tag = 0;
    dwarf_tag(die, &tag, &error);

    // Fuzz dwarf_die_text
    char *ret_name = 0;
    dwarf_die_text(die, attrnum, &ret_name, &error);

    // Fuzz dwarf_bitoffset
    Dwarf_Unsigned bit_offset = 0;
    dwarf_bitoffset(die, &attrnum, &bit_offset, &error);

    // Cleanup
    if (die) {
        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }
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

        LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    