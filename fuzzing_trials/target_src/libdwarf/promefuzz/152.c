// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_fde_exception_info at dwarf_frame.c:689:1 in libdwarf.h
// dwarf_get_cie_index at dwarf_frame.c:363:1 in libdwarf.h
// dwarf_get_cie_of_fde at dwarf_frame.c:349:1 in libdwarf.h
// dwarf_get_fde_list_eh at dwarf_frame.c:389:1 in libdwarf.h
// dwarf_get_fde_n at dwarf_frame.c:1249:1 in libdwarf.h
// dwarf_get_fde_info_for_all_regs3_b at dwarf_frame.c:905:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_debug() {
    return NULL; // Return NULL as we cannot instantiate an incomplete type
}

static Dwarf_Fde create_dummy_fde() {
    return NULL; // Return NULL as we cannot instantiate an incomplete type
}

static Dwarf_Cie create_dummy_cie() {
    return NULL; // Return NULL as we cannot instantiate an incomplete type
}

int LLVMFuzzerTestOneInput_152(const uint8_t *Data, size_t Size) {
    Dwarf_Error error = NULL;
    Dwarf_Signed offset = 0;
    Dwarf_Signed index = 0;
    Dwarf_Cie cie_returned = NULL;
    Dwarf_Fde *fde_data = NULL;
    Dwarf_Cie *cie_data = NULL;
    Dwarf_Signed cie_count = 0;
    Dwarf_Signed fde_count = 0;
    Dwarf_Fde returned_fde = NULL;
    Dwarf_Regtable3 reg_table;
    Dwarf_Addr row_pc = 0;
    Dwarf_Bool has_more_rows = 0;
    Dwarf_Addr subsequent_pc = 0;

    // Create dummy structures
    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Fde fde = create_dummy_fde();
    Dwarf_Cie cie = create_dummy_cie();

    // Allocate space for reg_table
    reg_table.rt3_reg_table_size = 16; // Arbitrary size
    reg_table.rt3_rules = (struct Dwarf_Regtable_Entry3_s *)calloc(reg_table.rt3_reg_table_size, sizeof(struct Dwarf_Regtable_Entry3_s));
    if (!reg_table.rt3_rules) {
        goto cleanup;
    }

    // Fuzz dwarf_get_fde_exception_info
    if (fde) {
        dwarf_get_fde_exception_info(fde, &offset, &error);
    }

    // Fuzz dwarf_get_cie_index
    if (cie) {
        dwarf_get_cie_index(cie, &index, &error);
    }

    // Fuzz dwarf_get_cie_of_fde
    if (fde) {
        dwarf_get_cie_of_fde(fde, &cie_returned, &error);
    }

    // Fuzz dwarf_get_fde_list_eh
    dwarf_get_fde_list_eh(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &error);

    // Fuzz dwarf_get_fde_n
    if (fde_data) {
        dwarf_get_fde_n(fde_data, 0, &returned_fde, &error);
    }

    // Fuzz dwarf_get_fde_info_for_all_regs3_b
    if (fde) {
        dwarf_get_fde_info_for_all_regs3_b(fde, 0, &reg_table, &row_pc, &has_more_rows, &subsequent_pc, &error);
    }

cleanup:
    if (reg_table.rt3_rules) free(reg_table.rt3_rules);
    if (fde_data) free(fde_data);
    if (cie_data) free(cie_data);

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

        LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    