// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_dealloc_error at dwarf_alloc.c:875:1 in libdwarf.h
// dwarf_set_stringcheck at dwarf_init_finish.c:185:1 in libdwarf.h
// dwarf_get_die_section_name at dwarf_die_deliv.c:3551:1 in libdwarf.h
// dwarf_set_reloc_application at dwarf_init_finish.c:177:1 in libdwarf.h
// dwarf_get_string_section_name at dwarf_line.c:1172:1 in libdwarf.h
// dwarf_init_b at dwarf_generic_init.c:447:1 in libdwarf.h
// dwarf_finish at dwarf_generic_init.c:536:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "libdwarf.h"

static void handle_error(Dwarf_Error error) {
    if (error) {
        dwarf_dealloc_error(NULL, error);
    }
}

static int fuzz_dwarf_set_stringcheck(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;
    int check_value = *(int *)Data;
    dwarf_set_stringcheck(check_value);
    return 0;
}

static int fuzz_dwarf_get_die_section_name(Dwarf_Debug dbg, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Bool)) return 0;
    Dwarf_Bool is_info = *(Dwarf_Bool *)Data;
    const char *section_name = NULL;
    Dwarf_Error error = NULL;
    dwarf_get_die_section_name(dbg, is_info, &section_name, &error);
    handle_error(error);
    return 0;
}

static int fuzz_dwarf_set_reloc_application(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;
    int apply_value = *(int *)Data;
    dwarf_set_reloc_application(apply_value);
    return 0;
}

static int fuzz_dwarf_get_string_section_name(Dwarf_Debug dbg) {
    const char *section_name_out = NULL;
    Dwarf_Error error = NULL;
    dwarf_get_string_section_name(dbg, &section_name_out, &error);
    handle_error(error);
    return 0;
}

static int fuzz_dwarf_init_b(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) return 0;

    write(fd, Data, Size);
    lseek(fd, 0, SEEK_SET);

    unsigned int groupnumber = DW_GROUPNUMBER_ANY;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    int res = dwarf_init_b(fd, groupnumber, NULL, NULL, &dbg, &error);

    if (res == DW_DLV_OK) {
        fuzz_dwarf_get_die_section_name(dbg, Data, Size);
        fuzz_dwarf_get_string_section_name(dbg);
        dwarf_finish(dbg);
    }

    handle_error(error);
    close(fd);
    return 0;
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    fuzz_dwarf_set_stringcheck(Data, Size);
    fuzz_dwarf_set_reloc_application(Data, Size);
    fuzz_dwarf_init_b(Data, Size);
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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    