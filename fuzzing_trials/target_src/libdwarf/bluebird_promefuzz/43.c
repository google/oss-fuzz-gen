#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Off)) {
        return 0;
    }

    write_dummy_file(Data, Size);

    // Since we cannot allocate memory for incomplete types, we will use NULL pointers
    Dwarf_Global dw_global = NULL;
    Dwarf_Die dw_die = NULL;
    Dwarf_Error dw_error = NULL;
    Dwarf_Off dw_die_offset = 0;
    Dwarf_Off dw_return_offset = 0;
    Dwarf_Bool dw_is_info = 0;
    int dw_category = 0;
    Dwarf_Off dw_offset_pub_header = 0;
    Dwarf_Unsigned dw_length_size = 0;
    Dwarf_Unsigned dw_length_pub = 0;
    Dwarf_Unsigned dw_version = 0;
    Dwarf_Unsigned dw_header_info_offset = 0;
    Dwarf_Unsigned dw_info_length = 0;
    Dwarf_Off dw_cu_header_offset = 0;

    // Fuzz the functions with NULL pointers
    dwarf_global_die_offset(dw_global, &dw_die_offset, &dw_error);
    dwarf_get_globals_header(dw_global, &dw_category, &dw_offset_pub_header,
                             &dw_length_size, &dw_length_pub, &dw_version,
                             &dw_header_info_offset, &dw_info_length, &dw_error);
    dwarf_global_cu_offset(dw_global, &dw_cu_header_offset, &dw_error);

    dwarf_dietype_offset(dw_die, &dw_return_offset, &dw_is_info, &dw_error);
    dwarf_dieoffset(dw_die, &dw_return_offset, &dw_error);

    if (dw_error) {
        dwarf_errno(dw_error);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from dwarf_dieoffset to dwarf_dnames_abbrevtable
    Dwarf_Bool ret_dwarf_addr_form_is_indexed_gfqcm = dwarf_addr_form_is_indexed(DW_DLE_RELOC_SECTION_MISMATCH);
    if (ret_dwarf_addr_form_is_indexed_gfqcm < 0){
    	return 0;
    }
    Dwarf_Bool ret_dwarf_addr_form_is_indexed_tswhi = dwarf_addr_form_is_indexed(DW_DLE_DEBUG_FORM_HANDLING_INCOMPLETE);
    if (ret_dwarf_addr_form_is_indexed_tswhi < 0){
    	return 0;
    }
    Dwarf_Unsigned ret_dwarf_errno_relii = dwarf_errno(dw_error);
    if (ret_dwarf_errno_relii < 0){
    	return 0;
    }
    int ret_dwarf_dnames_abbrevtable_rychj = dwarf_dnames_abbrevtable(0, (unsigned long long )dw_is_info, (unsigned long long *)&dw_is_info, &dw_version, &dw_length_pub, dw_return_offset, (unsigned short *)&ret_dwarf_addr_form_is_indexed_gfqcm, (unsigned short *)&ret_dwarf_addr_form_is_indexed_tswhi, &ret_dwarf_errno_relii);
    if (ret_dwarf_dnames_abbrevtable_rychj < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
