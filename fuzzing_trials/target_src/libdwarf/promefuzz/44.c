// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path at dwarf_generic_init.c:160:5 in libdwarf.h
// dwarf_dnames_header at dwarf_debugnames.c:768:1 in libdwarf.h
// dwarf_dnames_entrypool at dwarf_debugnames.c:1650:5 in libdwarf.h
// dwarf_dnames_offsets at dwarf_debugnames.c:982:1 in libdwarf.h
// dwarf_dnames_abbrevtable at dwarf_debugnames.c:1299:1 in libdwarf.h
// dwarf_dnames_bucket at dwarf_debugnames.c:1193:1 in libdwarf.h
// dwarf_dealloc_dnames at dwarf_debugnames.c:889:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    write_dummy_file(Data, Size);

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Unsigned offset = *(Dwarf_Unsigned *)Data;
    Dwarf_Dnames_Head dn_head = 0;
    Dwarf_Off next_table_offset = 0;

    // Initialize Dwarf_Debug
    if (dwarf_init_path("./dummy_file", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error) != DW_DLV_OK) {
        return 0;
    }

    // Attempt to read .debug_names header
    if (dwarf_dnames_header(dbg, 0, &dn_head, &next_table_offset, &error) == DW_DLV_OK) {
        // Fuzz dwarf_dnames_entrypool
        Dwarf_Unsigned abbrev_code = 0, value_count = 0, index_of_abbrev = 0, offset_of_initial_value = 0;
        Dwarf_Half tag = 0;
        dwarf_dnames_entrypool(dn_head, offset, &abbrev_code, &tag, &value_count, &index_of_abbrev, &offset_of_initial_value, &error);

        // Fuzz dwarf_dnames_offsets
        Dwarf_Unsigned header_offset = 0, cu_table_offset = 0, tu_local_offset = 0, foreign_tu_offset = 0;
        Dwarf_Unsigned bucket_offset = 0, hashes_offset = 0, stringoffsets_offset = 0, entryoffsets_offset = 0;
        Dwarf_Unsigned abbrev_table_offset = 0, entry_pool_offset = 0;
        dwarf_dnames_offsets(dn_head, &header_offset, &cu_table_offset, &tu_local_offset, &foreign_tu_offset,
                             &bucket_offset, &hashes_offset, &stringoffsets_offset, &entryoffsets_offset,
                             &abbrev_table_offset, &entry_pool_offset, &error);

        // Fuzz dwarf_dnames_abbrevtable
        Dwarf_Unsigned abbrev_offset = 0, abbrev_code2 = 0, abbrev_tag = 0, idxattr_count = 0;
        Dwarf_Half idxattr_array[10] = {0}, form_array[10] = {0};
        dwarf_dnames_abbrevtable(dn_head, offset, &abbrev_offset, &abbrev_code2, &abbrev_tag, 10, idxattr_array, form_array, &idxattr_count);

        // Fuzz dwarf_dnames_bucket
        Dwarf_Unsigned index = 0, indexcount = 0;
        dwarf_dnames_bucket(dn_head, offset, &index, &indexcount, &error);

        // Deallocate Dwarf_Dnames_Head
        dwarf_dealloc_dnames(dn_head);
    }

    // Finish Dwarf_Debug
    dwarf_finish(dbg);

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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    