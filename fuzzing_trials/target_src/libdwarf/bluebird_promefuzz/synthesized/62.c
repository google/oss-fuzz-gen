#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

/* Dummy DIE structure for testing purposes */
struct Dwarf_Die_s {
    void *di_debug_ptr;
    void *di_abbrev_list;
    void *di_cu_context;
    Dwarf_Unsigned di_abbrev_code;
    Dwarf_Bool di_is_info;
};

static Dwarf_Die create_dummy_die() {
    Dwarf_Die die = (Dwarf_Die)malloc(sizeof(struct Dwarf_Die_s));
    if (!die) {
        fprintf(stderr, "Failed to allocate memory for Dwarf_Die\n");
        exit(EXIT_FAILURE);
    }
    memset(die, 0, sizeof(struct Dwarf_Die_s));
    return die;
}

static void cleanup_dummy_die(Dwarf_Die die) {
    free(die);
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Die die = create_dummy_die();
    Dwarf_Error error = 0;

    // Fuzz dwarf_get_die_section_name_b
    const char *sec_name = NULL;
    int res = dwarf_get_die_section_name_b(die, &sec_name, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_get_die_section_name_b failed\n");
    }

    // Fuzz dwarf_diename
    char *diename = NULL;
    res = dwarf_diename(die, &diename, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_diename failed\n");
    }

    // Fuzz dwarf_get_die_address_size
    Dwarf_Half addr_size = 0;
    res = dwarf_get_die_address_size(die, &addr_size, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_get_die_address_size failed\n");
    }

    // Fuzz dwarf_tag
    Dwarf_Half return_tag = 0;
    res = dwarf_tag(die, &return_tag, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_tag failed\n");
    }

    // Fuzz dwarf_get_line_section_name_from_die
    const char *line_sec_name = NULL;
    res = dwarf_get_line_section_name_from_die(die, &line_sec_name, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_get_line_section_name_from_die failed\n");
    }

    // Fuzz dwarf_die_text
    char *ret_name = NULL;
    Dwarf_Half attr_num = (Dwarf_Half)(Data[0] % 0xFFFF); // Use part of Data as attribute number
    res = dwarf_die_text(die, attr_num, &ret_name, &error);
    if (res != DW_DLV_OK && res != DW_DLV_NO_ENTRY) {
        fprintf(stderr, "dwarf_die_text failed\n");
    }

    cleanup_dummy_die(die);
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
