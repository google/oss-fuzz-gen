// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_convert_to_global_offset at dwarf_form.c:338:1 in libdwarf.h
// dwarf_global_formref_b at dwarf_form.c:748:1 in libdwarf.h
// dwarf_get_debug_addr_index at dwarf_form.c:1093:1 in libdwarf.h
// dwarf_global_formref at dwarf_form.c:733:1 in libdwarf.h
// dwarf_formref at dwarf_form.c:463:1 in libdwarf.h
// dwarf_formaddr at dwarf_form.c:1317:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

static void cleanup(Dwarf_Debug dbg, Dwarf_Error error) {
    if (error) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Off)) {
        return 0;
    }

    // Create dummy objects with NULL as we cannot access internal structures
    Dwarf_Debug dbg = NULL;
    Dwarf_Attribute attr = NULL;
    Dwarf_Error error = NULL;

    // Extract offset from the input data
    Dwarf_Off offset = *(Dwarf_Off*)Data;
    Dwarf_Off return_offset;
    Dwarf_Bool is_info;
    Dwarf_Unsigned index;
    Dwarf_Addr addr;

    // Fuzz dwarf_convert_to_global_offset
    dwarf_convert_to_global_offset(attr, offset, &return_offset, &error);
    cleanup(dbg, error);

    // Fuzz dwarf_global_formref_b
    dwarf_global_formref_b(attr, &return_offset, &is_info, &error);
    cleanup(dbg, error);

    // Fuzz dwarf_get_debug_addr_index
    dwarf_get_debug_addr_index(attr, &index, &error);
    cleanup(dbg, error);

    // Fuzz dwarf_global_formref
    dwarf_global_formref(attr, &return_offset, &error);
    cleanup(dbg, error);

    // Fuzz dwarf_formref
    dwarf_formref(attr, &return_offset, &is_info, &error);
    cleanup(dbg, error);

    // Fuzz dwarf_formaddr
    dwarf_formaddr(attr, &addr, &error);
    cleanup(dbg, error);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    