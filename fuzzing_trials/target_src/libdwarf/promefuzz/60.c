// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_str_offsets_value_by_index at dwarf_str_offsets.c:145:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_next_str_offsets_table at dwarf_str_offsets.c:501:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_str_offsets_statistics at dwarf_str_offsets.c:674:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_open_str_offsets_table_access at dwarf_str_offsets.c:85:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_close_str_offsets_table_access at dwarf_str_offsets.c:131:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_init_path_dl_a at dwarf_generic_init.c:261:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <libdwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static int fuzz_dwarf_str_offsets_value_by_index(Dwarf_Str_Offsets_Table table, Dwarf_Unsigned index) {
    Dwarf_Unsigned entry_value;
    Dwarf_Error error;
    int res = dwarf_str_offsets_value_by_index(table, index, &entry_value, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
    }
    return res;
}

static int fuzz_dwarf_next_str_offsets_table(Dwarf_Str_Offsets_Table table) {
    Dwarf_Unsigned unit_length, unit_length_offset, table_start_offset, table_value_count;
    Dwarf_Half entry_size, version, padding;
    Dwarf_Error error;
    int res = dwarf_next_str_offsets_table(table, &unit_length, &unit_length_offset, &table_start_offset, &entry_size, &version, &padding, &table_value_count, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
    }
    return res;
}

static int fuzz_dwarf_str_offsets_statistics(Dwarf_Str_Offsets_Table table) {
    Dwarf_Unsigned wasted_byte_count, table_count;
    Dwarf_Error error;
    int res = dwarf_str_offsets_statistics(table, &wasted_byte_count, &table_count, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
    }
    return res;
}

static int fuzz_dwarf_open_str_offsets_table_access(Dwarf_Debug dbg, Dwarf_Str_Offsets_Table *table) {
    Dwarf_Error error;
    int res = dwarf_open_str_offsets_table_access(dbg, table, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(dbg, error);
    }
    return res;
}

static int fuzz_dwarf_close_str_offsets_table_access(Dwarf_Str_Offsets_Table table) {
    Dwarf_Error error;
    int res = dwarf_close_str_offsets_table_access(table, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
    }
    return res;
}

static int fuzz_dwarf_init_path_dl_a(const char *path, Dwarf_Debug *dbg) {
    char true_path_out_buffer[4096];
    unsigned char dl_path_source;
    Dwarf_Error error;
    int res = dwarf_init_path_dl_a(path, true_path_out_buffer, sizeof(true_path_out_buffer), 0, 0, NULL, NULL, dbg, NULL, 0, &dl_path_source, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(NULL, error);
    }
    return res;
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) return 0;

    write(fd, Data, Size);
    lseek(fd, 0, SEEK_SET);

    Dwarf_Debug dbg = NULL;
    if (fuzz_dwarf_init_path_dl_a("./dummy_file", &dbg) != DW_DLV_OK) {
        close(fd);
        return 0;
    }

    Dwarf_Str_Offsets_Table table;
    if (fuzz_dwarf_open_str_offsets_table_access(dbg, &table) == DW_DLV_OK) {
        fuzz_dwarf_next_str_offsets_table(table);
        fuzz_dwarf_str_offsets_statistics(table);
        fuzz_dwarf_str_offsets_value_by_index(table, 0);
        fuzz_dwarf_close_str_offsets_table_access(table);
    }

    dwarf_finish(dbg);
    close(fd);
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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    