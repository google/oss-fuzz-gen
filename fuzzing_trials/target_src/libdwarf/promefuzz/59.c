// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_get_globals at dwarf_global.c:1238:1 in libdwarf.h
// dwarf_global_die_offset at dwarf_global.c:1340:1 in libdwarf.h
// dwarf_global_cu_offset at dwarf_global.c:1364:1 in libdwarf.h
// dwarf_globname at dwarf_global.c:1321:1 in libdwarf.h
// dwarf_globals_by_type at dwarf_global.c:1124:1 in libdwarf.h
// dwarf_global_die_offset at dwarf_global.c:1340:1 in libdwarf.h
// dwarf_global_cu_offset at dwarf_global.c:1364:1 in libdwarf.h
// dwarf_globname at dwarf_global.c:1321:1 in libdwarf.h
// dwarf_get_pubtypes at dwarf_global.c:1257:1 in libdwarf.h
// dwarf_global_die_offset at dwarf_global.c:1340:1 in libdwarf.h
// dwarf_global_cu_offset at dwarf_global.c:1364:1 in libdwarf.h
// dwarf_globname at dwarf_global.c:1321:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_debug() {
    return NULL; // Return NULL as we cannot allocate an incomplete type
}

static Dwarf_Global create_dummy_global() {
    return NULL; // Return NULL as we cannot allocate an incomplete type
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Off)) {
        return 0;
    }

    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Global global = create_dummy_global();
    Dwarf_Error error = NULL;
    Dwarf_Global *globals = NULL;
    Dwarf_Signed number_of_globals = 0;
    Dwarf_Off die_offset = 0;
    Dwarf_Off cu_offset = 0;
    char *returned_name = NULL;

    // Test dwarf_get_globals
    int res = dwarf_get_globals(dbg, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK) {
        for (Dwarf_Signed i = 0; i < number_of_globals; ++i) {
            // Test dwarf_global_die_offset
            res = dwarf_global_die_offset(globals[i], &die_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_global_cu_offset
            res = dwarf_global_cu_offset(globals[i], &cu_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_globname
            res = dwarf_globname(globals[i], &returned_name, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }
        }
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    // Test dwarf_globals_by_type
    res = dwarf_globals_by_type(dbg, DW_GL_GLOBALS, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK) {
        for (Dwarf_Signed i = 0; i < number_of_globals; ++i) {
            // Test dwarf_global_die_offset
            res = dwarf_global_die_offset(globals[i], &die_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_global_cu_offset
            res = dwarf_global_cu_offset(globals[i], &cu_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_globname
            res = dwarf_globname(globals[i], &returned_name, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }
        }
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    // Test dwarf_get_pubtypes
    res = dwarf_get_pubtypes(dbg, &globals, &number_of_globals, &error);
    if (res == DW_DLV_OK) {
        for (Dwarf_Signed i = 0; i < number_of_globals; ++i) {
            // Test dwarf_global_die_offset
            res = dwarf_global_die_offset(globals[i], &die_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_global_cu_offset
            res = dwarf_global_cu_offset(globals[i], &cu_offset, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }

            // Test dwarf_globname
            res = dwarf_globname(globals[i], &returned_name, &error);
            if (res != DW_DLV_OK) {
                // Handle error
            }
        }
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    // Cleanup
    if (globals) {
        dwarf_dealloc(dbg, globals, DW_DLA_LIST);
    }
    if (returned_name) {
        dwarf_dealloc(dbg, returned_name, DW_DLA_STRING);
    }
    if (error) {
        dwarf_dealloc_error(dbg, error);
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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    