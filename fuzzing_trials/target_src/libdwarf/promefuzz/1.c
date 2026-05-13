// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_DEFAULTED_name at dwarf_names.c:2303:1 in libdwarf.h
// dwarf_get_GNUIKIND_name at dwarf_names.c:2479:1 in libdwarf.h
// dwarf_get_GNUIVIS_name at dwarf_names.c:2463:1 in libdwarf.h
// dwarf_get_IDX_name at dwarf_names.c:2322:1 in libdwarf.h
// dwarf_get_ISA_name at dwarf_names.c:3472:1 in libdwarf.h
// dwarf_get_LLEX_name at dwarf_names.c:2367:1 in libdwarf.h
// dwarf_get_LNCT_name at dwarf_names.c:3309:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "libdwarf.h"

#define DW_DLV_OK 0
#define DW_DLV_NO_ENTRY -1

static void invoke_dwarf_get_name_functions(unsigned int value) {
    const char *name_out;

    // Call dwarf_get_DEFAULTED_name four times
    for (int i = 0; i < 4; ++i) {
        if (dwarf_get_DEFAULTED_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_GNUIKIND_name four times
    for (int i = 0; i < 4; ++i) {
        if (dwarf_get_GNUIKIND_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_GNUIVIS_name three times
    for (int i = 0; i < 3; ++i) {
        if (dwarf_get_GNUIVIS_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_IDX_name four times
    for (int i = 0; i < 4; ++i) {
        if (dwarf_get_IDX_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_ISA_name four times
    for (int i = 0; i < 4; ++i) {
        if (dwarf_get_ISA_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_LLEX_name four times
    for (int i = 0; i < 4; ++i) {
        if (dwarf_get_LLEX_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }

    // Call dwarf_get_LNCT_name six times
    for (int i = 0; i < 6; ++i) {
        if (dwarf_get_LNCT_name(value, &name_out) == DW_DLV_OK) {
            // Process the name_out if needed
        }
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int value = *(unsigned int *)Data;
    invoke_dwarf_get_name_functions(value);

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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    