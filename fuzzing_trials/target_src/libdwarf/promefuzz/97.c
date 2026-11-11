// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_cie_info_b at dwarf_frame.c:715:1 in libdwarf.h
// dwarf_get_fde_augmentation_data at dwarf_frame.c:1630:1 in libdwarf.h
// dwarf_get_cie_augmentation_data at dwarf_frame.c:1594:1 in libdwarf.h
// dwarf_expand_frame_instructions at dwarf_frame.c:1343:1 in libdwarf.h
// dwarf_dealloc_frame_instr_head at dwarf_frame.c:1952:1 in libdwarf.h
// dwarf_cie_section_offset at dwarf_frame.c:1557:1 in libdwarf.h
// dwarf_get_fde_range at dwarf_frame.c:640:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf.h>

static void prepare_dummy_data(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Cie)) {
        return 0;
    }

    prepare_dummy_data(Data, Size);

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Cie cie = (Dwarf_Cie)Data;
    Dwarf_Unsigned cie_length = 0;
    Dwarf_Small cie_version = 0;
    char *augmenter = NULL;
    Dwarf_Unsigned code_alignment_factor = 0;
    Dwarf_Signed data_alignment_factor = 0;
    Dwarf_Half return_address_register_rule = 0;
    Dwarf_Small *initial_instructions = NULL;
    Dwarf_Unsigned initial_instructions_length = 0;
    Dwarf_Half offset_size = 0;

    int res = dwarf_get_cie_info_b(cie, &cie_length, &cie_version, &augmenter,
                                   &code_alignment_factor, &data_alignment_factor,
                                   &return_address_register_rule, &initial_instructions,
                                   &initial_instructions_length, &offset_size, &error);
    if (res == DW_DLV_OK) {
        // Handle successful retrieval
    } else {
        // Handle error
    }

    Dwarf_Fde fde = (Dwarf_Fde)Data;
    Dwarf_Small *augdata = NULL;
    Dwarf_Unsigned augdata_len = 0;

    res = dwarf_get_fde_augmentation_data(fde, &augdata, &augdata_len, &error);
    if (res == DW_DLV_OK || res == DW_DLV_NO_ENTRY) {
        // Handle successful retrieval or no entry
    } else {
        // Handle error
    }

    augdata = NULL;
    augdata_len = 0;

    res = dwarf_get_cie_augmentation_data(cie, &augdata, &augdata_len, &error);
    if (res == DW_DLV_OK || res == DW_DLV_NO_ENTRY) {
        // Handle successful retrieval or no entry
    } else {
        // Handle error
    }

    Dwarf_Frame_Instr_Head instr_head = NULL;
    Dwarf_Unsigned instr_count = 0;

    res = dwarf_expand_frame_instructions(cie, initial_instructions, initial_instructions_length,
                                          &instr_head, &instr_count, &error);
    if (res == DW_DLV_OK) {
        dwarf_dealloc_frame_instr_head(instr_head);
    } else {
        // Handle error
    }

    Dwarf_Off cie_off = 0;

    res = dwarf_cie_section_offset(dbg, cie, &cie_off, &error);
    if (res == DW_DLV_OK) {
        // Handle successful retrieval
    } else {
        // Handle error
    }

    Dwarf_Addr low_pc = 0;
    Dwarf_Unsigned func_length = 0;
    Dwarf_Small *fde_bytes = NULL;
    Dwarf_Unsigned fde_byte_length = 0;
    Dwarf_Off cie_offset = 0;
    Dwarf_Signed cie_index = 0;
    Dwarf_Off fde_offset = 0;

    res = dwarf_get_fde_range(fde, &low_pc, &func_length, &fde_bytes, &fde_byte_length,
                              &cie_offset, &cie_index, &fde_offset, &error);
    if (res == DW_DLV_OK) {
        // Handle successful retrieval
    } else {
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

        LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    