// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_open_str_offsets_table_access at dwarf_str_offsets.c:85:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_get_tied_dbg at dwarf_generic_init.c:641:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_init_path_dl at dwarf_generic_init.c:218:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_init_path_dl_a at dwarf_generic_init.c:261:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_return_empty_pubnames at dwarf_global.c:1672:1 in libdwarf.h
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf.h>

static void write_dummy_file(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

static int fuzz_dwarf_open_str_offsets_table_access(Dwarf_Debug dbg) {
    Dwarf_Str_Offsets_Table table = NULL;
    Dwarf_Error error = NULL;
    int res = dwarf_open_str_offsets_table_access(dbg, &table, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
    return res;
}

static int fuzz_dwarf_get_tied_dbg(Dwarf_Debug dbg) {
    Dwarf_Debug tied_dbg = NULL;
    Dwarf_Error error = NULL;
    int res = dwarf_get_tied_dbg(dbg, &tied_dbg, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }
    return res;
}

static int fuzz_dwarf_init_path_dl(const char *path) {
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    unsigned char path_source = 0;
    int res = dwarf_init_path_dl(path, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, NULL, 0, &path_source, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(NULL, error);
    }
    if (dbg) {
        dwarf_finish(dbg);
    }
    return res;
}

static int fuzz_dwarf_init_path_dl_a(const char *path) {
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    unsigned char path_source = 0;
    int res = dwarf_init_path_dl_a(path, NULL, 0, DW_GROUPNUMBER_ANY, 0, NULL, NULL, &dbg, NULL, 0, &path_source, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(NULL, error);
    }
    if (dbg) {
        dwarf_finish(dbg);
    }
    return res;
}

static int fuzz_dwarf_return_empty_pubnames(Dwarf_Debug dbg) {
    return dwarf_return_empty_pubnames(dbg, 1);
}

static int fuzz_dwarf_init_b(int fd) {
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    int res = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(NULL, error);
    }
    if (dbg) {
        dwarf_finish(dbg);
    }
    return res;
}

int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file(Data, Size);

    int fd = open("./dummy_file", O_RDONLY);
    if (fd < 0) return 0;

    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error) == DW_DLV_OK) {
        fuzz_dwarf_open_str_offsets_table_access(dbg);
        fuzz_dwarf_get_tied_dbg(dbg);
        fuzz_dwarf_return_empty_pubnames(dbg);
        dwarf_finish(dbg);
    } else if (error) {
        dwarf_dealloc_error(NULL, error);
    }

    close(fd);

    fuzz_dwarf_init_path_dl("./dummy_file");
    fuzz_dwarf_init_path_dl_a("./dummy_file");

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    