#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void fuzz_dwarf_str_offsets_value_by_index(Dwarf_Str_Offsets_Table table, Dwarf_Unsigned index) {
    Dwarf_Unsigned entry_value;
    Dwarf_Error error;

    int res = dwarf_str_offsets_value_by_index(table, index, &entry_value, &error);
    if (res == DW_DLV_ERROR) {
        // Handle error
    }
}

static void fuzz_dwarf_decode_leb128(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char *leb = (char *)Data;
    Dwarf_Unsigned leblen, outval;
    char *endptr = (char *)Data + Size;

    int res = dwarf_decode_leb128(leb, &leblen, &outval, endptr);
    if (res == DW_DLV_ERROR) {
        // Handle error
    }
}

static void fuzz_dwarf_encode_leb128(Dwarf_Unsigned val) {
    char space[10];
    int nbytes;
    int res = dwarf_encode_leb128(val, &nbytes, space, sizeof(space));
    if (res == DW_DLV_ERROR) {
        // Handle error
    }
}

static void fuzz_dwarf_get_section_max_offsets_d(Dwarf_Debug dbg) {
    Dwarf_Unsigned debug_info_size, debug_abbrev_size, debug_line_size, debug_loc_size, debug_aranges_size;
    Dwarf_Unsigned debug_macinfo_size, debug_pubnames_size, debug_str_size, debug_frame_size, debug_ranges_size;
    Dwarf_Unsigned debug_pubtypes_size, debug_types_size, debug_macro_size, debug_str_offsets_size, debug_sup_size;
    Dwarf_Unsigned debug_cu_index_size, debug_tu_index_size, debug_names_size, debug_loclists_size, debug_rnglists_size;

    int res = dwarf_get_section_max_offsets_d(dbg, &debug_info_size, &debug_abbrev_size, &debug_line_size, &debug_loc_size, &debug_aranges_size,
                                              &debug_macinfo_size, &debug_pubnames_size, &debug_str_size, &debug_frame_size, &debug_ranges_size,
                                              &debug_pubtypes_size, &debug_types_size, &debug_macro_size, &debug_str_offsets_size, &debug_sup_size,
                                              &debug_cu_index_size, &debug_tu_index_size, &debug_names_size, &debug_loclists_size, &debug_rnglists_size);
    if (res == DW_DLV_NO_ENTRY) {
        // Handle no entry error
    }
}

static void fuzz_dwarf_get_str(Dwarf_Debug dbg, Dwarf_Off offset) {
    char *string;
    Dwarf_Signed strlen_of_string;
    Dwarf_Error error;

    int res = dwarf_get_str(dbg, offset, &string, &strlen_of_string, &error);
    if (res == DW_DLV_ERROR) {
        // Handle error
    }
}

static void fuzz_dwarf_find_macro_value_start(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char *macro_string = (char *)malloc(Size + 1);
    if (!macro_string) return;

    memcpy(macro_string, Data, Size);
    macro_string[Size] = '\0';  // Ensure null-termination

    char *value_start = dwarf_find_macro_value_start(macro_string);
    if (value_start == NULL) {
        // Handle error
    }

    free(macro_string);
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    // Prepare a dummy Dwarf_Debug and Dwarf_Str_Offsets_Table for testing
    Dwarf_Debug dbg = NULL;
    Dwarf_Str_Offsets_Table table = NULL;

    // Fuzz each function
    fuzz_dwarf_str_offsets_value_by_index(table, Size);
    fuzz_dwarf_decode_leb128(Data, Size);
    fuzz_dwarf_encode_leb128(Size);
    fuzz_dwarf_get_section_max_offsets_d(dbg);
    fuzz_dwarf_get_str(dbg, Size);
    fuzz_dwarf_find_macro_value_start(Data, Size);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
