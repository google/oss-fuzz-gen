// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_get_endian_copy_function at dwarf_util.c:293:1 in libdwarf.h
// dwarf_dieoffset at dwarf_query.c:118:1 in libdwarf.h
// dwarf_siblingof_b at dwarf_die_deliv.c:2749:1 in libdwarf.h
// dwarf_insert_harmless_error at dwarf_harmless.c:142:1 in libdwarf.h
// dwarf_add_debuglink_global_path at dwarf_debuglink.c:1066:1 in libdwarf.h
// dwarf_get_ranges_baseaddress at dwarf_ranges.c:438:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void cleanup_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_finish(dbg);
    }
}

static void cleanup_die(Dwarf_Die die) {
    // No specific cleanup function for Dwarf_Die as it's managed by Dwarf_Debug
}

int LLVMFuzzerTestOneInput_116(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Debug dbg = NULL;
    Dwarf_Die die = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Off return_offset = 0;
    Dwarf_Bool is_info = (Size % 2 == 0);
    Dwarf_Die sibling_die = NULL;
    Dwarf_Bool known_base = 0;
    Dwarf_Unsigned baseaddress = 0;
    Dwarf_Bool at_ranges_offset_present = 0;
    Dwarf_Unsigned at_ranges_offset = 0;

    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;

    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    int res = dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Fuzz dwarf_get_endian_copy_function
    void (*endian_copy_func)(void *, const void *, unsigned long);
    endian_copy_func = dwarf_get_endian_copy_function(dbg);
    if (endian_copy_func) {
        char src[4] = {0};
        char dest[4] = {0};
        endian_copy_func(dest, src, 4);
    }

    // Fuzz dwarf_dieoffset
    res = dwarf_dieoffset(die, &return_offset, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        // Handle error
    }

    // Fuzz dwarf_siblingof_b
    res = dwarf_siblingof_b(dbg, die, is_info, &sibling_die, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        // Handle error
    }

    // Fuzz dwarf_insert_harmless_error
    char harmless_error[] = "harmless error";
    dwarf_insert_harmless_error(dbg, harmless_error);

    // Fuzz dwarf_add_debuglink_global_path
    const char *path = "./dummy_path";
    res = dwarf_add_debuglink_global_path(dbg, path, &error);
    if (res != DW_DLV_OK) {
        // Handle error
    }

    // Fuzz dwarf_get_ranges_baseaddress
    res = dwarf_get_ranges_baseaddress(dbg, die, &known_base, &baseaddress, &at_ranges_offset_present, &at_ranges_offset, &error);
    if (res != DW_DLV_OK) {
        // Handle error
    }

    cleanup_debug(dbg);
    cleanup_die(die);

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

        LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    