// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_EH_name at dwarf_names.c:3695:1 in libdwarf.h
// dwarf_get_LNE_name at dwarf_names.c:3412:1 in libdwarf.h
// dwarf_get_INL_name at dwarf_names.c:3255:1 in libdwarf.h
// dwarf_get_AT_name at dwarf_names.c:564:1 in libdwarf.h
// dwarf_get_CHILDREN_name at dwarf_names.c:4090:1 in libdwarf.h
// dwarf_get_children_name at dwarf_names.c:394:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "libdwarf.h"

static void fuzz_dwarf_get_EH_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_EH_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

static void fuzz_dwarf_get_LNE_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_LNE_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

static void fuzz_dwarf_get_INL_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_INL_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

static void fuzz_dwarf_get_AT_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_AT_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

static void fuzz_dwarf_get_CHILDREN_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_CHILDREN_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

static void fuzz_dwarf_get_children_name(unsigned int dw_val_in) {
    const char *name = NULL;
    int result = dwarf_get_children_name(dw_val_in, &name);
    if (result == DW_DLV_OK && name) {
        // Successfully retrieved the name
    }
}

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return 0;

    unsigned int dw_val_in = *(unsigned int *)Data;

    fuzz_dwarf_get_EH_name(dw_val_in);
    fuzz_dwarf_get_LNE_name(dw_val_in);
    fuzz_dwarf_get_INL_name(dw_val_in);
    fuzz_dwarf_get_AT_name(dw_val_in);
    fuzz_dwarf_get_CHILDREN_name(dw_val_in);
    fuzz_dwarf_get_children_name(dw_val_in);

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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    