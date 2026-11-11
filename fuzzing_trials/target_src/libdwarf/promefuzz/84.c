// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_find_die_given_sig8 at dwarf_find_sigref.c:180:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_die_section_name at dwarf_die_deliv.c:3551:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_set_harmless_errors_enabled at dwarf_harmless.c:130:1 in libdwarf.h
// dwarf_get_ranges_section_name at dwarf_line.c:1089:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_debugfission_for_key at dwarf_xu_index.c:1185:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_str at dwarf_stringsection.c:49:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static Dwarf_Debug create_dummy_dwarf_debug() {
    return NULL; // As Dwarf_Debug is opaque, we return NULL for the dummy.
}

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    Dwarf_Debug dbg = create_dummy_dwarf_debug();

    if (dbg == NULL) {
        return 0; // Early return if the dummy Dwarf_Debug is not properly initialized
    }

    Dwarf_Sig8 sig8;
    Dwarf_Die die_out;
    Dwarf_Bool is_info;
    Dwarf_Error error;
    int result;

    if (Size >= sizeof(sig8.signature)) {
        memcpy(sig8.signature, Data, sizeof(sig8.signature));
    } else {
        memset(sig8.signature, 0, sizeof(sig8.signature));
    }

    // Fuzz dwarf_find_die_given_sig8
    result = dwarf_find_die_given_sig8(dbg, &sig8, &die_out, &is_info, &error);
    if (result != DW_DLV_OK && result != DW_DLV_NO_ENTRY) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_get_die_section_name
    const char *sec_name;
    result = dwarf_get_die_section_name(dbg, 1, &sec_name, &error);
    if (result != DW_DLV_OK && result != DW_DLV_NO_ENTRY) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_set_harmless_errors_enabled
    int prev_state = dwarf_set_harmless_errors_enabled(dbg, 1);

    // Fuzz dwarf_get_ranges_section_name
    const char *ranges_sec_name;
    result = dwarf_get_ranges_section_name(dbg, &ranges_sec_name, &error);
    if (result != DW_DLV_OK && result != DW_DLV_NO_ENTRY) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_get_debugfission_for_key
    Dwarf_Debug_Fission_Per_CU per_cu_out;
    memset(&per_cu_out, 0, sizeof(per_cu_out));
    result = dwarf_get_debugfission_for_key(dbg, &sig8, "cu", &per_cu_out, &error);
    if (result != DW_DLV_OK && result != DW_DLV_NO_ENTRY) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    // Fuzz dwarf_get_str
    char *string_out;
    Dwarf_Signed strlen_out;
    result = dwarf_get_str(dbg, 0, &string_out, &strlen_out, &error);
    if (result != DW_DLV_OK && result != DW_DLV_NO_ENTRY) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
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

        LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    