// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_TAG_name at dwarf_names.c:12:1 in libdwarf.h
// dwarf_get_ATE_name at dwarf_names.c:2176:1 in libdwarf.h
// dwarf_get_RLE_name at dwarf_names.c:2429:1 in libdwarf.h
// dwarf_get_LANG_name at dwarf_names.c:2719:1 in libdwarf.h
// dwarf_get_ORD_name at dwarf_names.c:3277:1 in libdwarf.h
// dwarf_get_CFA_name at dwarf_names.c:3568:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

static void fuzz_dwarf_get_TAG_name(unsigned int value) {
    const char *name;
    if (dwarf_get_TAG_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the TAG name
    }
}

static void fuzz_dwarf_get_ATE_name(unsigned int value) {
    const char *name;
    if (dwarf_get_ATE_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the ATE name
    }
}

static void fuzz_dwarf_get_RLE_name(unsigned int value) {
    const char *name;
    if (dwarf_get_RLE_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the RLE name
    }
}

static void fuzz_dwarf_get_LANG_name(unsigned int value) {
    const char *name;
    if (dwarf_get_LANG_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the LANG name
    }
}

static void fuzz_dwarf_get_ORD_name(unsigned int value) {
    const char *name;
    if (dwarf_get_ORD_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the ORD name
    }
}

static void fuzz_dwarf_get_CFA_name(unsigned int value) {
    const char *name;
    if (dwarf_get_CFA_name(value, &name) == DW_DLV_OK) {
        // Successfully retrieved the CFA name
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int value = 0;
    for (size_t i = 0; i < sizeof(unsigned int) && i < Size; ++i) {
        value = (value << 8) | Data[i];
    }

    fuzz_dwarf_get_TAG_name(value);
    fuzz_dwarf_get_ATE_name(value);
    fuzz_dwarf_get_RLE_name(value);
    fuzz_dwarf_get_LANG_name(value);
    fuzz_dwarf_get_ORD_name(value);
    fuzz_dwarf_get_CFA_name(value);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    