// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_init_path_dl_a at dwarf_generic_init.c:261:1 in libdwarf.h
// dwarf_open_str_offsets_table_access at dwarf_str_offsets.c:85:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_next_str_offsets_table at dwarf_str_offsets.c:501:1 in libdwarf.h
// dwarf_str_offsets_value_by_index at dwarf_str_offsets.c:145:1 in libdwarf.h
// dwarf_str_offsets_statistics at dwarf_str_offsets.c:674:1 in libdwarf.h
// dwarf_close_str_offsets_table_access at dwarf_str_offsets.c:131:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char dummy_data[] = "dummy_data";
        fwrite(dummy_data, 1, sizeof(dummy_data), file);
        fclose(file);
    }
}

static Dwarf_Debug init_dwarf_debug(const char *path, Dwarf_Error *error) {
    Dwarf_Debug dbg = 0;
    char true_path[1024] = {0};
    dwarf_init_path_dl_a(path, true_path, sizeof(true_path), 0, 0, NULL, NULL, &dbg, NULL, 0, NULL, error);
    return dbg;
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    write_dummy_file();

    Dwarf_Error error = 0;
    Dwarf_Debug dbg = init_dwarf_debug("./dummy_file", &error);
    if (!dbg) {
        return 0;
    }

    Dwarf_Str_Offsets_Table table = 0;
    if (dwarf_open_str_offsets_table_access(dbg, &table, &error) != DW_DLV_OK) {
        dwarf_dealloc_error(dbg, error);
        dwarf_finish(dbg);
        return 0;
    }

    Dwarf_Unsigned unit_length, unit_length_offset, table_start_offset, table_value_count;
    Dwarf_Half entry_size, version, padding;
    if (dwarf_next_str_offsets_table(table, &unit_length, &unit_length_offset, &table_start_offset, &entry_size, &version, &padding, &table_value_count, &error) == DW_DLV_OK) {
        
        Dwarf_Unsigned entry_value = 0;
        Dwarf_Unsigned index = *(Dwarf_Unsigned *)Data % table_value_count;

        dwarf_str_offsets_value_by_index(table, index, &entry_value, &error);

        Dwarf_Unsigned wasted_byte_count = 0;
        Dwarf_Unsigned table_count = 0;
        dwarf_str_offsets_statistics(table, &wasted_byte_count, &table_count, &error);
    }

    dwarf_close_str_offsets_table_access(table, &error);
    dwarf_dealloc_error(dbg, error);
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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    