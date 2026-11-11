#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "libdwarf.h"

static void maybe_write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Sig8) + 1) {
        return 0;
    }

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Sig8 sig8;
    memcpy(&sig8, Data, sizeof(Dwarf_Sig8));
    const char *sig_type = (const char *)(Data + sizeof(Dwarf_Sig8));

    Dwarf_Die die_out = 0;
    Dwarf_Bool is_info = 0;

    // Fuzz dwarf_find_die_given_sig8
    int res = dwarf_find_die_given_sig8(dbg, &sig8, &die_out, &is_info, &error);
    if (res == DW_DLV_OK && die_out) {
        // Fuzz dwarf_siblingof_c
        Dwarf_Die sibling_die = 0;
        res = dwarf_siblingof_c(die_out, &sibling_die, &error);
        if (res == DW_DLV_OK && sibling_die) {
            // Fuzz dwarf_get_die_infotypes_flag
            Dwarf_Bool flag = dwarf_get_die_infotypes_flag(sibling_die);
        }
    }

    // Fuzz dwarf_die_from_hash_signature
    Dwarf_Die returned_CU_die = 0;
    res = dwarf_die_from_hash_signature(dbg, &sig8, sig_type, &returned_CU_die, &error);
    if (res == DW_DLV_OK && returned_CU_die) {
        // Fuzz dwarf_siblingof_b
        Dwarf_Die sibling_die_b = 0;
        res = dwarf_siblingof_b(dbg, returned_CU_die, is_info, &sibling_die_b, &error);
    }

    // Fuzz dwarf_offdie_b
    Dwarf_Off offset = 0;
    Dwarf_Die return_die = 0;
    res = dwarf_offdie_b(dbg, offset, is_info, &return_die, &error);

    // Clean up
    if (die_out) {
        dwarf_dealloc(dbg, die_out, DW_DLA_DIE);
    }
    if (returned_CU_die) {
        dwarf_dealloc(dbg, returned_CU_die, DW_DLA_DIE);
    }
    if (return_die) {
        dwarf_dealloc(dbg, return_die, DW_DLA_DIE);
    }

    // Optionally write the input data to a file for further analysis
    maybe_write_dummy_file(Data, Size);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
