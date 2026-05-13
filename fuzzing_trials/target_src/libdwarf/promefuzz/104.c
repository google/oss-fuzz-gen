// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_object_finish at dwarf_init_finish.c:1187:1 in libdwarf.h
// dwarf_set_tied_dbg at dwarf_generic_init.c:597:1 in libdwarf.h
// dwarf_get_globals at dwarf_global.c:1238:1 in libdwarf.h
// dwarf_next_cu_header_e at dwarf_die_deliv.c:1123:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "libdwarf.h"

static Dwarf_Debug open_dwarf_debug(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    int res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        close(fd);
        return NULL;
    }
    return dbg;
}

static void close_dwarf_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_object_finish(dbg);
    }
}

int LLVMFuzzerTestOneInput_104(const uint8_t *Data, size_t Size) {
    // Prepare a dummy file
    const char *dummy_filename = "./dummy_file";
    FILE *dummy_file = fopen(dummy_filename, "wb");
    if (!dummy_file) {
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Initialize Dwarf_Debug structures
    Dwarf_Debug split_dbg = open_dwarf_debug(dummy_filename);
    Dwarf_Debug tied_dbg = open_dwarf_debug(dummy_filename);
    if (!split_dbg || !tied_dbg) {
        close_dwarf_debug(split_dbg);
        close_dwarf_debug(tied_dbg);
        return 0;
    }

    // Fuzz dwarf_set_tied_dbg
    Dwarf_Error error = NULL;
    dwarf_set_tied_dbg(split_dbg, tied_dbg, &error);

    // Fuzz dwarf_get_globals
    Dwarf_Global *globals = NULL;
    Dwarf_Signed number_of_globals = 0;
    dwarf_get_globals(split_dbg, &globals, &number_of_globals, &error);

    // Fuzz dwarf_next_cu_header_e
    Dwarf_Die cu_die = NULL;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Off abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half length_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 type_signature;
    Dwarf_Unsigned typeoffset = 0;
    Dwarf_Unsigned next_cu_header_offset = 0;
    Dwarf_Half header_cu_type = 0;
    dwarf_next_cu_header_e(split_dbg, 1, &cu_die, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header_offset, &header_cu_type, &error);

    // Clean up
    close_dwarf_debug(split_dbg);
    close_dwarf_debug(tied_dbg);

    // Remove dummy file
    remove(dummy_filename);

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

        LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    