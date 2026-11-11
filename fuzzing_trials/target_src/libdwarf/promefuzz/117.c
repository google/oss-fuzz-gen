// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_siblingof_b at dwarf_die_deliv.c:2749:1 in libdwarf.h
// dwarf_attrlist at dwarf_query.c:351:1 in libdwarf.h
// dwarf_global_formref_b at dwarf_form.c:748:1 in libdwarf.h
// dwarf_attr_offset at dwarf_query.c:1784:1 in libdwarf.h
// dwarf_formsdata at dwarf_form.c:1583:1 in libdwarf.h
// dwarf_attrlist at dwarf_query.c:351:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_formflag at dwarf_form.c:1374:1 in libdwarf.h
// dwarf_formref at dwarf_form.c:463:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libdwarf.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static void cleanup(Dwarf_Attribute attr, Dwarf_Die die, Dwarf_Error error, Dwarf_Debug dbg) {
    if (attr) {
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }
    if (die) {
        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }
    if (error) {
        dwarf_dealloc_error(dbg, error);
    }
    if (dbg) {
        dwarf_finish(dbg);
    }
}

int LLVMFuzzerTestOneInput_117(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    write_dummy_file(Data, Size);

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Attribute attr = 0;
    Dwarf_Die die = 0;
    Dwarf_Off return_offset = 0;
    Dwarf_Bool is_info = 0;
    Dwarf_Signed returned_val = 0;
    Dwarf_Attribute *attrbuf = NULL;
    Dwarf_Signed attrcount = 0;
    Dwarf_Bool returned_bool = 0;

    // Initialize Dwarf_Debug
    int res = dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        cleanup(attr, die, error, dbg);
        return 0;
    }

    // Create dummy attribute and DIE
    res = dwarf_siblingof_b(dbg, NULL, 1, &die, &error); // Use 1 instead of true
    if (res == DW_DLV_OK) {
        res = dwarf_attrlist(die, &attrbuf, &attrcount, &error);
        if (res == DW_DLV_OK && attrcount > 0) {
            attr = attrbuf[0];
        }
    }

    // Test dwarf_global_formref_b
    dwarf_global_formref_b(attr, &return_offset, &is_info, &error);

    // Test dwarf_attr_offset
    dwarf_attr_offset(die, attr, &return_offset, &error);

    // Test dwarf_formsdata
    dwarf_formsdata(attr, &returned_val, &error);

    // Test dwarf_attrlist
    dwarf_attrlist(die, &attrbuf, &attrcount, &error);
    if (attrbuf) {
        dwarf_dealloc(dbg, attrbuf, DW_DLA_LIST);
    }

    // Test dwarf_formflag
    dwarf_formflag(attr, &returned_bool, &error);

    // Test dwarf_formref
    dwarf_formref(attr, &return_offset, &is_info, &error);

    cleanup(attr, die, error, dbg);
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

        LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    