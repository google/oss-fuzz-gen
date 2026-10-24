// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_fde_info_for_reg3_c at dwarf_frame.c:1032:1 in libdwarf.h
// dwarf_get_fde_info_for_cfa_reg3_c at dwarf_frame.c:1185:1 in libdwarf.h
// dwarf_get_fde_instr_bytes at dwarf_frame.c:1219:1 in libdwarf.h
// dwarf_get_fde_range at dwarf_frame.c:640:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Addr)) {
        return 0;
    }

    Dwarf_Fde fde = NULL;  // Assume a valid Dwarf_Fde is obtained from somewhere

    Dwarf_Half table_column = 0;
    Dwarf_Addr pc_requested = *(Dwarf_Addr *)Data;
    Dwarf_Small value_type;
    Dwarf_Unsigned offset_relevant;
    Dwarf_Unsigned reg;
    Dwarf_Signed offset;
    Dwarf_Block block_content;
    Dwarf_Addr row_pc_out;
    Dwarf_Bool has_more_rows;
    Dwarf_Addr subsequent_pc;
    Dwarf_Error error;

    int res = dwarf_get_fde_info_for_reg3_c(
        fde, table_column, pc_requested, &value_type,
        &offset_relevant, &reg, &offset, &block_content,
        &row_pc_out, &has_more_rows, &subsequent_pc, &error
    );

    if (res == DW_DLV_OK) {
        // Successfully retrieved FDE info
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    res = dwarf_get_fde_info_for_cfa_reg3_c(
        fde, pc_requested, &value_type, &offset_relevant, &reg,
        &offset, &block_content, &row_pc_out, &has_more_rows,
        &subsequent_pc, &error
    );

    if (res == DW_DLV_OK) {
        // Successfully retrieved CFA info
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    Dwarf_Small *outinstrs;
    Dwarf_Unsigned outlen;
    res = dwarf_get_fde_instr_bytes(fde, &outinstrs, &outlen, &error);

    if (res == DW_DLV_OK) {
        // Successfully retrieved instruction bytes
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

    Dwarf_Addr low_pc;
    Dwarf_Unsigned func_length;
    Dwarf_Small *fde_bytes;
    Dwarf_Unsigned fde_byte_length;
    Dwarf_Off cie_offset;
    Dwarf_Signed cie_index;
    Dwarf_Off fde_offset;

    res = dwarf_get_fde_range(
        fde, &low_pc, &func_length, &fde_bytes,
        &fde_byte_length, &cie_offset, &cie_index,
        &fde_offset, &error
    );

    if (res == DW_DLV_OK) {
        // Successfully retrieved FDE range
    } else if (res == DW_DLV_ERROR) {
        // Handle error
    }

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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    