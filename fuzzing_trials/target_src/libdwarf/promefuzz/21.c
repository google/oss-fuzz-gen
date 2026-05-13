// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_xu_index_header at dwarf_xu_index.c:172:1 in libdwarf.h
// dwarf_get_xu_index_section_type at dwarf_xu_index.c:457:5 in libdwarf.h
// dwarf_get_xu_section_offset at dwarf_xu_index.c:706:1 in libdwarf.h
// dwarf_get_xu_section_names at dwarf_xu_index.c:648:1 in libdwarf.h
// dwarf_get_xu_hash_entry at dwarf_xu_index.c:475:5 in libdwarf.h
// dwarf_dealloc_xu_header at dwarf_xu_index.c:1229:1 in libdwarf.h
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

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Debug dbg = NULL;
    Dwarf_Xu_Index_Header xuhdr = NULL;
    Dwarf_Error error = NULL;

    write_dummy_file(Data, Size);

    const char *section_type = "cu";
    Dwarf_Unsigned version_number, section_count, units_count, hash_slots_count;
    const char *sect_name = NULL;

    int res = dwarf_get_xu_index_header(dbg, section_type, &xuhdr, &version_number, &section_count, &units_count, &hash_slots_count, &sect_name, &error);
    if (res == DW_DLV_OK) {
        const char *typename = NULL;
        const char *sectionname = NULL;
        res = dwarf_get_xu_index_section_type(xuhdr, &typename, &sectionname, &error);

        if (res == DW_DLV_OK) {
            Dwarf_Unsigned sec_offset, sec_size;
            res = dwarf_get_xu_section_offset(xuhdr, 1, 0, &sec_offset, &sec_size, &error);

            if (res == DW_DLV_OK) {
                Dwarf_Unsigned SECT_number;
                const char *SECT_name = NULL;
                res = dwarf_get_xu_section_names(xuhdr, 0, &SECT_number, &SECT_name, &error);

                if (res == DW_DLV_OK) {
                    Dwarf_Sig8 hash_value;
                    Dwarf_Unsigned index_to_sections;
                    res = dwarf_get_xu_hash_entry(xuhdr, 0, &hash_value, &index_to_sections, &error);
                }
            }
        }
    }

    if (xuhdr) {
        dwarf_dealloc_xu_header(xuhdr);
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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    