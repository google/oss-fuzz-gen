// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_object_finish at dwarf_init_finish.c:1187:1 in libdwarf.h
// dwarf_set_tied_dbg at dwarf_generic_init.c:597:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_get_die_section_name at dwarf_die_deliv.c:3551:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_object_init_b at dwarf_init_finish.c:1056:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_object_finish at dwarf_init_finish.c:1187:1 in libdwarf.h
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_object_finish at dwarf_init_finish.c:1187:1 in libdwarf.h
// dwarf_next_cu_header_e at dwarf_die_deliv.c:1123:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_debug() {
    // Create a dummy Dwarf_Debug object for testing
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = 0;
    int res = dwarf_init_b(-1, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc_error(dbg, error);
        }
        return NULL;
    }
    return dbg;
}

static void cleanup_debug(Dwarf_Debug dbg) {
    if (dbg) {
        dwarf_object_finish(dbg);
    }
}

static void test_dwarf_set_tied_dbg(Dwarf_Debug split_dbg, Dwarf_Debug tied_dbg) {
    Dwarf_Error error = 0;
    int res = dwarf_set_tied_dbg(split_dbg, tied_dbg, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(split_dbg, error);
    }
}

static void test_dwarf_get_die_section_name(Dwarf_Debug dbg) {
    Dwarf_Error error = 0;
    const char *sec_name = NULL;
    int res = dwarf_get_die_section_name(dbg, 1, &sec_name, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
}

static void test_dwarf_object_init_b() {
    Dwarf_Obj_Access_Interface_a obj_access;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = 0;
    int res = dwarf_object_init_b(&obj_access, NULL, NULL, DW_GROUPNUMBER_ANY, &dbg, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
    if (dbg) {
        dwarf_object_finish(dbg);
    }
}

static void test_dwarf_init_b() {
    FILE *dummy_file = fopen("./dummy_file", "wb+");
    if (!dummy_file) {
        return;
    }
    int fd = fileno(dummy_file);
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = 0;
    int res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
    if (dbg) {
        dwarf_object_finish(dbg);
    }
    fclose(dummy_file);
}

static void test_dwarf_next_cu_header_e(Dwarf_Debug dbg) {
    Dwarf_Error error = 0;
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

    int res = dwarf_next_cu_header_e(dbg, 1, &cu_die, &cu_header_length, &version_stamp,
                                     &abbrev_offset, &address_size, &length_size,
                                     &extension_size, &type_signature, &typeoffset,
                                     &next_cu_header_offset, &header_cu_type, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
}

int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size) {
    Dwarf_Debug split_dbg = create_dummy_debug();
    Dwarf_Debug tied_dbg = create_dummy_debug();

    if (!split_dbg || !tied_dbg) {
        cleanup_debug(split_dbg);
        cleanup_debug(tied_dbg);
        return 0;
    }

    test_dwarf_set_tied_dbg(split_dbg, tied_dbg);
    test_dwarf_get_die_section_name(split_dbg);
    test_dwarf_object_init_b();
    test_dwarf_init_b();
    test_dwarf_next_cu_header_e(split_dbg);

    cleanup_debug(split_dbg);
    cleanup_debug(tied_dbg);

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

        LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    