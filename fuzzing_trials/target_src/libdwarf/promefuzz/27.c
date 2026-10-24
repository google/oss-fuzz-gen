// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_xu_index_section_type at dwarf_xu_index.c:457:5 in libdwarf.h
// dwarf_get_xu_section_offset at dwarf_xu_index.c:706:1 in libdwarf.h
// dwarf_get_xu_index_header at dwarf_xu_index.c:172:1 in libdwarf.h
// dwarf_get_xu_section_names at dwarf_xu_index.c:648:1 in libdwarf.h
// dwarf_get_xu_hash_entry at dwarf_xu_index.c:475:5 in libdwarf.h
// dwarf_dealloc_xu_header at dwarf_xu_index.c:1229:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static Dwarf_Debug create_dummy_debug() {
    return NULL; // As we cannot instantiate an incomplete type, return NULL.
}

static Dwarf_Xu_Index_Header create_dummy_xu_index_header() {
    return NULL; // As we cannot instantiate an incomplete type, return NULL.
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned) * 2) return 0;

    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Xu_Index_Header xuhdr = create_dummy_xu_index_header();
    Dwarf_Error error = NULL;
    const char *typename = NULL;
    const char *sectionname = NULL;
    Dwarf_Unsigned version_number = 0;
    Dwarf_Unsigned section_count = 0;
    Dwarf_Unsigned units_count = 0;
    Dwarf_Unsigned hash_slots_count = 0;
    Dwarf_Unsigned sec_offset = 0;
    Dwarf_Unsigned sec_size = 0;
    Dwarf_Unsigned SECT_number = 0;
    const char *SECT_name = NULL;
    Dwarf_Sig8 hash_value;
    Dwarf_Unsigned index_to_sections = 0;

    if (xuhdr) {
        dwarf_get_xu_index_section_type(xuhdr, &typename, &sectionname, &error);
        dwarf_get_xu_section_offset(xuhdr, Data[0], Data[1], &sec_offset, &sec_size, &error);
        dwarf_get_xu_index_header(dbg, "cu", &xuhdr, &version_number, &section_count, &units_count, &hash_slots_count, &sectionname, &error);
        dwarf_get_xu_section_names(xuhdr, Data[0], &SECT_number, &SECT_name, &error);
        dwarf_get_xu_hash_entry(xuhdr, Data[0], &hash_value, &index_to_sections, &error);

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

        LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    