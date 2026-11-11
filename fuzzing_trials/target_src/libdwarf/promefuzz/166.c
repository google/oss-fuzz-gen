// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path_a at dwarf_generic_init.c:142:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_set_default_address_size at dwarf_frame.c:1799:1 in libdwarf.h
// dwarf_set_harmless_errors_enabled at dwarf_harmless.c:130:1 in libdwarf.h
// dwarf_set_load_preference at dwarf_alloc.c:778:1 in libdwarf.h
// dwarf_gdbindex_addressarea_entry at dwarf_gdbindex.c:541:1 in libdwarf.h
// dwarf_get_pubtypes at dwarf_global.c:1257:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_dwarf_debug() {
    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    int res = dwarf_init_path_a("./dummy_file", NULL, 0, 0, 0, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        return NULL;
    }
    return dbg;
}

static void destroy_dummy_dwarf_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_finish(dbg);
    }
}

int LLVMFuzzerTestOneInput_166(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Debug dbg = create_dummy_dwarf_debug();
    if (!dbg) return 0;

    // Fuzz dwarf_set_default_address_size
    Dwarf_Small address_size = Data[0];
    dwarf_set_default_address_size(dbg, address_size);

    // Fuzz dwarf_set_harmless_errors_enabled
    int enable_errors = Data[0] % 2;
    dwarf_set_harmless_errors_enabled(dbg, enable_errors);

    // Fuzz dwarf_set_load_preference
    enum Dwarf_Sec_Alloc_Pref load_pref = (enum Dwarf_Sec_Alloc_Pref)(Data[0] % 3);
    dwarf_set_load_preference(load_pref);

    // Fuzz dwarf_gdbindex_addressarea_entry
    Dwarf_Gdbindex gdbindex = NULL;
    Dwarf_Unsigned low_address = 0, high_address = 0, cu_index = 0;
    Dwarf_Error error = 0;
    dwarf_gdbindex_addressarea_entry(gdbindex, 0, &low_address, &high_address, &cu_index, &error);

    // Fuzz dwarf_get_pubtypes
    Dwarf_Global* pubtypes = NULL;
    Dwarf_Signed number_of_pubtypes = 0;
    dwarf_get_pubtypes(dbg, &pubtypes, &number_of_pubtypes, &error);
    if (pubtypes) {
        free(pubtypes);
    }

    destroy_dummy_dwarf_debug(dbg);
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

        LLVMFuzzerTestOneInput_166(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    