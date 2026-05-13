// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_dietype_offset at dwarf_query.c:1244:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_die_CU_offset_range at dwarf_query.c:193:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_die_offsets at dwarf_query.c:162:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_die_abbrev_global_offset at dwarf_die_deliv.c:3447:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_arrayorder at dwarf_query.c:1766:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dieoffset at dwarf_query.c:118:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_siblingof_b at dwarf_die_deliv.c:2749:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

static Dwarf_Die create_dummy_die(Dwarf_Debug dbg) {
    Dwarf_Die die = NULL;
    Dwarf_Error error = NULL;
    dwarf_siblingof_b(dbg, NULL, 1, &die, &error); // Changed 'true' to '1' for boolean
    if (error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }
    return die;
}

static void destroy_dummy_die(Dwarf_Debug dbg, Dwarf_Die die) {
    if (die) {
        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }
}

int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Off) + sizeof(Dwarf_Unsigned) + sizeof(Dwarf_Bool)) {
        return 0;
    }

    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    if (dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(NULL, error, DW_DLA_ERROR);
        }
        return 0;
    }

    Dwarf_Die die = create_dummy_die(dbg);
    if (!die) {
        dwarf_finish(dbg); // Removed error argument
        return 0;
    }

    Dwarf_Off return_offset = 0;
    Dwarf_Bool is_info = 0;

    // Fuzz dwarf_dietype_offset
    int res = dwarf_dietype_offset(die, &return_offset, &is_info, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_die_CU_offset_range
    Dwarf_Off cu_header_offset = 0;
    Dwarf_Off cu_length_bytes = 0;
    res = dwarf_die_CU_offset_range(die, &cu_header_offset, &cu_length_bytes, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_die_offsets
    Dwarf_Off global_offset = 0;
    Dwarf_Off local_offset = 0;
    res = dwarf_die_offsets(die, &global_offset, &local_offset, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_die_abbrev_global_offset
    Dwarf_Off abbrev_offset = 0;
    Dwarf_Unsigned abbrev_count = 0;
    res = dwarf_die_abbrev_global_offset(die, &abbrev_offset, &abbrev_count, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_arrayorder
    Dwarf_Unsigned returned_order = 0;
    res = dwarf_arrayorder(die, &returned_order, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_dieoffset
    Dwarf_Off die_offset = 0;
    res = dwarf_dieoffset(die, &die_offset, &error);
    if (res != DW_DLV_OK && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    destroy_dummy_die(dbg, die);
    dwarf_finish(dbg); // Removed error argument
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

        LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    