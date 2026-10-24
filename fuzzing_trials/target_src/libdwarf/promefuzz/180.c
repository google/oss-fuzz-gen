// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_gdbindex_header at dwarf_gdbindex.c:169:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_gdbindex_cuvector_inner_attributes at dwarf_gdbindex.c:718:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_gdbindex_cuvector_instance_expand_value at dwarf_gdbindex.c:767:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_CU_dieoffset_given_die at dwarf_global.c:1653:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_gdbindex_string_by_offset at dwarf_gdbindex.c:792:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "libdwarf.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_180(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0; // Not enough data to proceed
    }

    write_dummy_file(Data, Size);

    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Unsigned version = 0;
    Dwarf_Unsigned cu_list_offset = 0;
    Dwarf_Unsigned types_cu_list_offset = 0;
    Dwarf_Unsigned address_area_offset = 0;
    Dwarf_Unsigned symbol_table_offset = 0;
    Dwarf_Unsigned constant_pool_offset = 0;
    Dwarf_Unsigned section_size = 0;
    const char *section_name = NULL;
    Dwarf_Gdbindex gdbindexptr = NULL;

    int res = dwarf_gdbindex_header(dbg, &gdbindexptr, &version, 
                                    &cu_list_offset, &types_cu_list_offset, 
                                    &address_area_offset, &symbol_table_offset, 
                                    &constant_pool_offset, &section_size, 
                                    &section_name, &error);

    if (res == DW_DLV_NO_ENTRY || res == DW_DLV_ERROR) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
        }
        return 0;
    }

    Dwarf_Unsigned field_value = 0;
    res = dwarf_gdbindex_cuvector_inner_attributes(gdbindexptr, 0, 0, 
                                                   &field_value, &error);

    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    Dwarf_Unsigned cu_index = 0;
    Dwarf_Unsigned symbol_kind = 0;
    Dwarf_Unsigned is_static = 0;
    res = dwarf_gdbindex_cuvector_instance_expand_value(gdbindexptr, field_value, 
                                                        &cu_index, &symbol_kind, 
                                                        &is_static, &error);

    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    Dwarf_Off return_offset = 0;
    Dwarf_Die die = NULL;
    res = dwarf_CU_dieoffset_given_die(die, &return_offset, &error);

    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    const char *string_ptr = NULL;
    res = dwarf_gdbindex_string_by_offset(gdbindexptr, 0, &string_ptr, &error);

    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    if (gdbindexptr) {
        dwarf_dealloc(dbg, gdbindexptr, DW_DLA_GDBINDEX);
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

        LLVMFuzzerTestOneInput_180(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    