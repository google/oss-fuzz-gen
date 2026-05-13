#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Half)) {
        return 0;
    }

    // Prepare a dummy Dwarf_Debug and Dwarf_Half value
    Dwarf_Debug dbg = NULL;  // Use NULL for testing as we can't instantiate Dwarf_Debug
    Dwarf_Half value = *(Dwarf_Half *)Data;

    // Test dwarf_set_frame_same_value
    Dwarf_Half prev_value = dwarf_set_frame_same_value(dbg, value);

    // Test dwarf_get_tied_dbg

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from dwarf_set_frame_same_value to dwarf_get_location_op_value_c
    Dwarf_Bool ret_dwarf_addr_form_is_indexed_phzmx = dwarf_addr_form_is_indexed(DW_DLE_SYMBOL_SECTION_SIZE_ERROR);
    if (ret_dwarf_addr_form_is_indexed_phzmx < 0){
    	return 0;
    }
    char* ret_dwarf_find_macro_value_start_vnuhe = dwarf_find_macro_value_start((char *)"r");
    if (ret_dwarf_find_macro_value_start_vnuhe == NULL){
    	return 0;
    }
    Dwarf_Bool ret_dwarf_addr_form_is_indexed_zdtfe = dwarf_addr_form_is_indexed(DW_DLE_DUP_ATTR_ON_DIE);
    if (ret_dwarf_addr_form_is_indexed_zdtfe < 0){
    	return 0;
    }
    Dwarf_Half ret_dwarf_global_tag_number_uugny = dwarf_global_tag_number(0);
    if (ret_dwarf_global_tag_number_uugny < 0){
    	return 0;
    }
    Dwarf_Unsigned ret_dwarf_die_abbrev_code_tiffq = dwarf_die_abbrev_code(0);
    if (ret_dwarf_die_abbrev_code_tiffq < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_dwarf_find_macro_value_start_vnuhe) {
    	return 0;
    }
    int ret_dwarf_get_location_op_value_c_zbbcg = dwarf_get_location_op_value_c(0, (unsigned long long )ret_dwarf_addr_form_is_indexed_phzmx, (unsigned char *)ret_dwarf_find_macro_value_start_vnuhe, (unsigned long long *)&ret_dwarf_addr_form_is_indexed_zdtfe, (unsigned long long *)&ret_dwarf_global_tag_number_uugny, (unsigned long long *)&prev_value, &ret_dwarf_die_abbrev_code_tiffq, NULL);
    if (ret_dwarf_get_location_op_value_c_zbbcg < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    Dwarf_Debug tied_dbg = NULL;
    Dwarf_Error error = NULL;
    int result = dwarf_get_tied_dbg(dbg, &tied_dbg, &error);

    // Test dwarf_set_frame_cfa_value
    Dwarf_Half prev_cfa_value = dwarf_set_frame_cfa_value(dbg, value);

    // Test dwarf_set_frame_rule_table_size
    Dwarf_Half prev_table_size = dwarf_set_frame_rule_table_size(dbg, value);

    // Test dwarf_set_frame_undefined_value
    Dwarf_Half prev_undefined_value = dwarf_set_frame_undefined_value(dbg, value);

    // Test dwarf_set_frame_rule_initial_value
    Dwarf_Half prev_initial_value = dwarf_set_frame_rule_initial_value(dbg, value);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from dwarf_set_frame_rule_initial_value to dwarf_global_name_offsets
    char* ret_dwarf_errmsg_by_number_hyknm = dwarf_errmsg_by_number(DW_DLE_ID);
    if (ret_dwarf_errmsg_by_number_hyknm == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_dwarf_errmsg_by_number_hyknm) {
    	return 0;
    }
    int ret_dwarf_global_name_offsets_bsiia = dwarf_global_name_offsets(0, &ret_dwarf_errmsg_by_number_hyknm, (unsigned long long *)&prev_initial_value, (unsigned long long *)&prev_undefined_value, &error);
    if (ret_dwarf_global_name_offsets_bsiia < 0){
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
