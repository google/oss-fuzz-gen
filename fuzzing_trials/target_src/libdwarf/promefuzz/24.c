// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_global_die_offset at dwarf_global.c:1340:1 in libdwarf.h
// dwarf_dietype_offset at dwarf_query.c:1244:1 in libdwarf.h
// dwarf_errno at dwarf_error.c:214:1 in libdwarf.h
// dwarf_get_globals_header at dwarf_global.c:1546:1 in libdwarf.h
// dwarf_dieoffset at dwarf_query.c:118:1 in libdwarf.h
// dwarf_global_cu_offset at dwarf_global.c:1364:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static Dwarf_Global create_dummy_global() {
    return NULL; // Return NULL for incomplete type
}

static Dwarf_Die create_dummy_die() {
    return NULL; // Return NULL for incomplete type
}

static Dwarf_Error create_dummy_error() {
    return NULL; // Return NULL for incomplete type
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Off)) return 0;

    Dwarf_Global global = create_dummy_global();
    Dwarf_Die die = create_dummy_die();
    Dwarf_Error error = create_dummy_error();

    Dwarf_Off offset = 0;
    Dwarf_Off cu_header_offset = 0;
    Dwarf_Bool is_info = 0;
    int category;
    Dwarf_Unsigned length_size, length_pub, version, header_info_offset, info_length;

    // Fuzz dwarf_global_die_offset
    if (global) {
        dwarf_global_die_offset(global, &offset, error);
    }

    // Fuzz dwarf_dietype_offset
    if (die) {
        dwarf_dietype_offset(die, &offset, &is_info, error);
    }

    // Fuzz dwarf_errno
    if (error) {
        dwarf_errno(error);
    }

    // Fuzz dwarf_get_globals_header
    if (global) {
        dwarf_get_globals_header(global, &category, &offset, &length_size, &length_pub, &version, &header_info_offset, &info_length, error);
    }

    // Fuzz dwarf_dieoffset
    if (die) {
        dwarf_dieoffset(die, &offset, error);
    }

    // Fuzz dwarf_global_cu_offset
    if (global) {
        dwarf_global_cu_offset(global, &cu_header_offset, error);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    