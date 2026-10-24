// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_siblingof_b at dwarf_die_deliv.c:2749:1 in libdwarf.h
// dwarf_die_offsets at dwarf_query.c:162:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_section_info_by_index_a at dwarf_init_finish.c:1858:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_section_info_by_name at dwarf_init_finish.c:1746:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_section_info_by_name_a at dwarf_init_finish.c:1760:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_section_info_by_index at dwarf_init_finish.c:1842:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_next_cu_header_e at dwarf_die_deliv.c:1123:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

static void cleanup(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Error error) {
    if (dbg) dwarf_finish(dbg);
    if (die) dwarf_dealloc(dbg, die, DW_DLA_DIE);
    if (error) dwarf_dealloc(dbg, error, DW_DLA_ERROR);
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    Dwarf_Debug dbg = 0;
    Dwarf_Die die = 0;
    Dwarf_Error error = 0;
    const char *dummy_path = "./dummy_file";

    // Initialize Dwarf_Debug
    if (dwarf_init_path(dummy_path, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error) != DW_DLV_OK) {
        cleanup(dbg, die, error);
        return 0;
    }

    // Create a dummy DIE
    if (dwarf_siblingof_b(dbg, NULL, 1, &die, &error) != DW_DLV_OK) {
        cleanup(dbg, die, error);
        return 0;
    }

    // Fuzzing dwarf_die_offsets
    Dwarf_Off global_offset = 0, local_offset = 0;
    if (dwarf_die_offsets(die, &global_offset, &local_offset, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    // Fuzzing dwarf_get_section_info_by_index_a
    const char *section_name = NULL;
    Dwarf_Addr section_addr = 0;
    Dwarf_Unsigned section_size = 0, section_flags = 0, section_offset = 0;
    if (dwarf_get_section_info_by_index_a(dbg, 0, &section_name, &section_addr, &section_size, &section_flags, &section_offset, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    // Fuzzing dwarf_get_section_info_by_name
    if (dwarf_get_section_info_by_name(dbg, ".debug_info", &section_addr, &section_size, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    // Fuzzing dwarf_get_section_info_by_name_a
    if (dwarf_get_section_info_by_name_a(dbg, ".debug_info", &section_addr, &section_size, &section_flags, &section_offset, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    // Fuzzing dwarf_get_section_info_by_index
    if (dwarf_get_section_info_by_index(dbg, 0, &section_name, &section_addr, &section_size, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    // Fuzzing dwarf_next_cu_header_e
    Dwarf_Die cu_die = 0;
    Dwarf_Unsigned cu_header_length = 0, typeoffset = 0, next_cu_header_offset = 0;
    Dwarf_Half version_stamp = 0, address_size = 0, length_size = 0, extension_size = 0, header_cu_type = 0;
    Dwarf_Off abbrev_offset = 0;
    Dwarf_Sig8 type_signature;
    if (dwarf_next_cu_header_e(dbg, 1, &cu_die, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header_offset, &header_cu_type, &error) != DW_DLV_OK) {
        if (error) {
            dwarf_dealloc(dbg, error, DW_DLA_ERROR);
            error = 0;
        }
    }

    cleanup(dbg, die, error);
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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    