// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dnames_header at dwarf_debugnames.c:768:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dnames_entrypool at dwarf_debugnames.c:1650:5 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dnames_sizes at dwarf_debugnames.c:916:5 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dnames_offsets at dwarf_debugnames.c:982:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dnames_bucket at dwarf_debugnames.c:1193:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_dnames_cu_table at dwarf_debugnames.c:1039:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_debug() {
    return NULL; // Returning NULL as we cannot instantiate Dwarf_Debug directly
}

static Dwarf_Dnames_Head create_dummy_dnames_head() {
    return NULL; // Returning NULL as we cannot instantiate Dwarf_Dnames_Head directly
}

static void cleanup(Dwarf_Debug dbg, Dwarf_Dnames_Head dn, Dwarf_Error error) {
    if (error) {
        dwarf_dealloc_error(NULL, error);
    }
}

int LLVMFuzzerTestOneInput_171(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Error error = NULL;
    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Dnames_Head dn = create_dummy_dnames_head();

    Dwarf_Unsigned offset = *((Dwarf_Unsigned *)Data);

    // Fuzz dwarf_dnames_entrypool
    Dwarf_Unsigned abbrev_code = 0;
    Dwarf_Half tag = 0;
    Dwarf_Unsigned value_count = 0;
    Dwarf_Unsigned index_of_abbrev = 0;
    Dwarf_Unsigned offset_of_initial_value = 0;
    int res = dwarf_dnames_entrypool(dn, offset, &abbrev_code, &tag, &value_count, &index_of_abbrev, &offset_of_initial_value, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    // Fuzz dwarf_dnames_sizes
    Dwarf_Unsigned comp_unit_count = 0;
    Dwarf_Unsigned local_type_unit_count = 0;
    Dwarf_Unsigned foreign_type_unit_count = 0;
    Dwarf_Unsigned bucket_count = 0;
    Dwarf_Unsigned name_count = 0;
    Dwarf_Unsigned abbrev_table_size = 0;
    Dwarf_Unsigned entry_pool_size = 0;
    Dwarf_Unsigned augmentation_string_size = 0;
    char *augmentation_string = NULL;
    Dwarf_Unsigned section_size = 0;
    Dwarf_Half table_version = 0;
    Dwarf_Half offset_size = 0;
    res = dwarf_dnames_sizes(dn, &comp_unit_count, &local_type_unit_count, &foreign_type_unit_count, &bucket_count, &name_count, &abbrev_table_size, &entry_pool_size, &augmentation_string_size, &augmentation_string, &section_size, &table_version, &offset_size, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    // Fuzz dwarf_dnames_offsets
    Dwarf_Unsigned header_offset = 0;
    Dwarf_Unsigned cu_table_offset = 0;
    Dwarf_Unsigned tu_local_offset = 0;
    Dwarf_Unsigned foreign_tu_offset = 0;
    Dwarf_Unsigned bucket_offset = 0;
    Dwarf_Unsigned hashes_offset = 0;
    Dwarf_Unsigned stringoffsets_offset = 0;
    Dwarf_Unsigned entryoffsets_offset = 0;
    Dwarf_Unsigned abbrev_table_offset = 0;
    Dwarf_Unsigned entry_pool_offset = 0;
    res = dwarf_dnames_offsets(dn, &header_offset, &cu_table_offset, &tu_local_offset, &foreign_tu_offset, &bucket_offset, &hashes_offset, &stringoffsets_offset, &entryoffsets_offset, &abbrev_table_offset, &entry_pool_offset, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    // Fuzz dwarf_dnames_bucket
    Dwarf_Unsigned index = 0;
    Dwarf_Unsigned indexcount = 0;
    res = dwarf_dnames_bucket(dn, offset, &index, &indexcount, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    // Fuzz dwarf_dnames_cu_table
    Dwarf_Unsigned cu_offset = 0;
    Dwarf_Sig8 sig;
    res = dwarf_dnames_cu_table(dn, "cu", offset, &cu_offset, &sig, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    // Fuzz dwarf_dnames_header
    Dwarf_Off next_table_offset = 0;
    Dwarf_Dnames_Head dn_head = NULL;
    res = dwarf_dnames_header(dbg, offset, &dn_head, &next_table_offset, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
        error = NULL;
    }

    cleanup(dbg, dn, error);
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

        LLVMFuzzerTestOneInput_171(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    