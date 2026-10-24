// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_child at dwarf_die_deliv.c:3138:1 in libdwarf.h
// dwarf_dealloc_die at dwarf_alloc.c:880:1 in libdwarf.h
// dwarf_siblingof_c at dwarf_die_deliv.c:2782:1 in libdwarf.h
// dwarf_dealloc_die at dwarf_alloc.c:880:1 in libdwarf.h
// dwarf_hasattr at dwarf_query.c:871:1 in libdwarf.h
// dwarf_tag at dwarf_query.c:210:1 in libdwarf.h
// dwarf_die_text at dwarf_query.c:834:1 in libdwarf.h
// dwarf_dealloc_die at dwarf_alloc.c:880:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Half)) {
        return 0;
    }

    Dwarf_Die die = NULL;
    Dwarf_Die child_die = NULL;
    Dwarf_Die sibling_die = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Half attrnum = *((Dwarf_Half *)Data);
    Dwarf_Bool has_attr;
    Dwarf_Half tag;
    char *die_text;

    // Fuzz dwarf_child
    if (dwarf_child(die, &child_die, &error) == 0) {
        dwarf_dealloc_die(child_die);
    }

    // Fuzz dwarf_siblingof_c
    if (dwarf_siblingof_c(die, &sibling_die, &error) == DW_DLV_OK) {
        dwarf_dealloc_die(sibling_die);
    }

    // Fuzz dwarf_hasattr
    if (dwarf_hasattr(die, attrnum, &has_attr, &error) == DW_DLV_OK) {
        // Do something with has_attr
    }

    // Fuzz dwarf_tag
    if (dwarf_tag(die, &tag, &error) == DW_DLV_OK) {
        // Do something with tag
    }

    // Fuzz dwarf_die_text
    if (dwarf_die_text(die, attrnum, &die_text, &error) == DW_DLV_OK) {
        // Do something with die_text
    }

    // Clean up
    dwarf_dealloc_die(die);

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

        LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    