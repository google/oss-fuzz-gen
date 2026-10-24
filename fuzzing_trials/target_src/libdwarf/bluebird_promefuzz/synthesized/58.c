#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void cleanup_dwarf_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_finish(dbg);
    }
}

static void cleanup_dwarf_global(Dwarf_Global *globals, Dwarf_Signed count) {
    if (globals) {
        for (Dwarf_Signed i = 0; i < count; ++i) {
            dwarf_dealloc(NULL, globals[i], DW_DLA_GLOBAL);
        }
        dwarf_dealloc(NULL, globals, DW_DLA_LIST);
    }
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    Dwarf_Debug dbg = NULL;
    Dwarf_Global *globals = NULL;
    Dwarf_Signed number_of_globals = 0;
    Dwarf_Error error = NULL;
    int res;

    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    res = dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Fuzz dwarf_get_pubtypes
    res = dwarf_get_pubtypes(dbg, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK && globals) {
        cleanup_dwarf_global(globals, number_of_globals);
    }

    // Fuzz dwarf_get_globals
    res = dwarf_get_globals(dbg, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK && globals) {
        cleanup_dwarf_global(globals, number_of_globals);
    }

    // Fuzz dwarf_globals_by_type
    res = dwarf_globals_by_type(dbg, DW_GL_GLOBALS, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK && globals) {
        cleanup_dwarf_global(globals, number_of_globals);
    }

    // Initialize Dwarf_Global
    Dwarf_Global global = NULL;
    Dwarf_Off die_offset = 0;
    char *returned_name = NULL;
    Dwarf_Off cu_header_offset = 0;

    // Fuzz dwarf_global_die_offset
    res = dwarf_global_die_offset(global, &die_offset, &error);

    // Fuzz dwarf_globname
    res = dwarf_globname(global, &returned_name, &error);
    if (res == DW_DLV_OK && returned_name) {
        // Process returned_name if needed
    }

    // Fuzz dwarf_global_cu_offset
    res = dwarf_global_cu_offset(global, &cu_header_offset, &error);

    // Cleanup Dwarf_Debug
    cleanup_dwarf_debug(dbg);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
