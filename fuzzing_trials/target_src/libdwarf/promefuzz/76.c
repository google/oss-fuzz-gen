// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_debug_addr_table at dwarf_debugaddr.c:80:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_debug_addr_by_index at dwarf_debugaddr.c:338:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc_debug_addr_table at dwarf_debugaddr.c:381:1 in libdwarf.h
// dwarf_get_debug_addr_index at dwarf_form.c:1093:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_formref at dwarf_form.c:463:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_formaddr at dwarf_form.c:1317:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
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

int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Debug_Addr_Table addr_table = NULL;
    Dwarf_Debug dbg = NULL;
    Dwarf_Unsigned section_offset = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Half version = 0;
    Dwarf_Small address_size = 0;
    Dwarf_Unsigned at_addr_base = 0;
    Dwarf_Unsigned entry_count = 0;
    Dwarf_Unsigned next_table_offset = 0;
    Dwarf_Error error = NULL;

    int res = dwarf_debug_addr_table(dbg, section_offset, &addr_table, &length, &version, &address_size, &at_addr_base, &entry_count, &next_table_offset, &error);
    if (res != DW_DLV_OK) {
        // Handle error
        if (error) {
            dwarf_dealloc(NULL, error, DW_DLA_ERROR);
        }
    }

    if (addr_table) {
        Dwarf_Unsigned address = 0;
        res = dwarf_debug_addr_by_index(addr_table, 0, &address, &error);
        if (res != DW_DLV_OK) {
            // Handle error
            if (error) {
                dwarf_dealloc(NULL, error, DW_DLA_ERROR);
            }
        }

        dwarf_dealloc_debug_addr_table(addr_table);
    }

    Dwarf_Attribute attr = NULL;
    Dwarf_Unsigned addr_index = 0;
    res = dwarf_get_debug_addr_index(attr, &addr_index, &error);
    if (res != DW_DLV_OK) {
        // Handle error
        if (error) {
            dwarf_dealloc(NULL, error, DW_DLA_ERROR);
        }
    }

    Dwarf_Off return_offset = 0;
    Dwarf_Bool is_info = 0;
    res = dwarf_formref(attr, &return_offset, &is_info, &error);
    if (res != DW_DLV_OK) {
        // Handle error
        if (error) {
            dwarf_dealloc(NULL, error, DW_DLA_ERROR);
        }
    }

    Dwarf_Addr returned_addr = 0;
    res = dwarf_formaddr(attr, &returned_addr, &error);
    if (res != DW_DLV_OK) {
        // Handle error
        if (error) {
            dwarf_dealloc(NULL, error, DW_DLA_ERROR);
        }
    }

    write_dummy_file(Data, Size);

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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    