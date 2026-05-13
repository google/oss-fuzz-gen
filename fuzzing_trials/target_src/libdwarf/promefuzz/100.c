// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_get_abbrev at dwarf_abbrev.c:297:1 in libdwarf.h
// dwarf_get_abbrev_children_flag at dwarf_abbrev.c:456:1 in libdwarf.h
// dwarf_get_abbrev_tag at dwarf_abbrev.c:443:1 in libdwarf.h
// dwarf_get_abbrev_entry_b at dwarf_abbrev.c:483:1 in libdwarf.h
// dwarf_get_abbrev_code at dwarf_abbrev.c:428:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static void cleanup_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_finish(dbg);
    }
}

static void cleanup_abbrev(Dwarf_Debug dbg, Dwarf_Abbrev abbrev) {
    if (abbrev) {
        dwarf_dealloc(dbg, abbrev, DW_DLA_ABBREV);
    }
}

int LLVMFuzzerTestOneInput_100(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Debug dbg = 0;
    Dwarf_Error err = 0;
    Dwarf_Unsigned offset = *((Dwarf_Unsigned *)Data);
    Dwarf_Abbrev returned_abbrev = NULL;
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned attr_count = 0;

    int res = dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Fuzz dwarf_get_abbrev
    res = dwarf_get_abbrev(dbg, offset, &returned_abbrev, &length, &attr_count, &err);
    if (res == DW_DLV_OK) {
        // Fuzz dwarf_get_abbrev_children_flag
        Dwarf_Signed children_flag = 0;
        res = dwarf_get_abbrev_children_flag(returned_abbrev, &children_flag, &err);

        // Fuzz dwarf_get_abbrev_tag
        Dwarf_Half tag_number = 0;
        res = dwarf_get_abbrev_tag(returned_abbrev, &tag_number, &err);

        // Fuzz dwarf_get_abbrev_entry_b
        Dwarf_Unsigned attr_num = 0;
        Dwarf_Unsigned form = 0;
        Dwarf_Signed implicit_const = 0;
        Dwarf_Off entry_offset = 0;
        res = dwarf_get_abbrev_entry_b(returned_abbrev, 0, 1, &attr_num, &form, &implicit_const, &entry_offset, &err);

        // Fuzz dwarf_get_abbrev_code
        Dwarf_Unsigned code_number = 0;
        res = dwarf_get_abbrev_code(returned_abbrev, &code_number, &err);

        // Clean up the returned abbrev
        cleanup_abbrev(dbg, returned_abbrev);
    }

    cleanup_debug(dbg);
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

        LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    