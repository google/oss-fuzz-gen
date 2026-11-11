// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_find_die_given_sig8 at dwarf_find_sigref.c:180:1 in libdwarf.h
// dwarf_get_die_section_name at dwarf_die_deliv.c:3551:1 in libdwarf.h
// dwarf_set_harmless_errors_enabled at dwarf_harmless.c:130:1 in libdwarf.h
// dwarf_get_ranges_section_name at dwarf_line.c:1089:1 in libdwarf.h
// dwarf_get_debugfission_for_key at dwarf_xu_index.c:1185:1 in libdwarf.h
// dwarf_get_str at dwarf_stringsection.c:49:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"

static void init_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char dummy_data[] = "dummy data for testing";
        fwrite(dummy_data, 1, sizeof(dummy_data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Sig8) + sizeof(int)) {
        return 0;
    }

    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Sig8 sig8;
    Dwarf_Die die_out = NULL;
    Dwarf_Bool is_info = 0;
    const char *section_name = NULL;
    Dwarf_Debug_Fission_Per_CU fission_data;
    char *debug_str = NULL;
    Dwarf_Signed str_len = 0;
    Dwarf_Off offset = 0;

    memcpy(&sig8, Data, sizeof(Dwarf_Sig8));
    int harmless_errors_flag = *(int *)(Data + sizeof(Dwarf_Sig8));

    // Initialize the dummy file
    init_dummy_file();

    // Initialize Dwarf_Debug
    if (dwarf_init_path("./dummy_file", NULL, 0, 0, 0, 0, &dbg, &error) != DW_DLV_OK) {
        return 0;
    }

    // Test dwarf_find_die_given_sig8
    dwarf_find_die_given_sig8(dbg, &sig8, &die_out, &is_info, &error);

    // Test dwarf_get_die_section_name
    dwarf_get_die_section_name(dbg, is_info, &section_name, &error);

    // Test dwarf_set_harmless_errors_enabled
    dwarf_set_harmless_errors_enabled(dbg, harmless_errors_flag);

    // Test dwarf_get_ranges_section_name
    dwarf_get_ranges_section_name(dbg, &section_name, &error);

    // Test dwarf_get_debugfission_for_key
    memset(&fission_data, 0, sizeof(fission_data));
    dwarf_get_debugfission_for_key(dbg, &sig8, "cu", &fission_data, &error);

    // Test dwarf_get_str
    dwarf_get_str(dbg, offset, &debug_str, &str_len, &error);

    // Cleanup
    dwarf_dealloc(dbg, die_out, DW_DLA_DIE);
    dwarf_dealloc(dbg, error, DW_DLA_ERROR);
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

        LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    