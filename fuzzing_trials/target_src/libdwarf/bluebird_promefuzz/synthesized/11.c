#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Error error = NULL;
    Dwarf_Line_Context dw_context = NULL;
    Dwarf_Unsigned dw_offset;
    Dwarf_Signed dw_index = Data[0] % 10; // Use first byte for index
    const char *dw_name;
    Dwarf_Unsigned dw_decl_file, dw_decl_line;
    Dwarf_Signed dw_count;
    Dwarf_Unsigned dw_version;
    Dwarf_Small dw_table_count;
    Dwarf_Die dw_cudie = NULL;
    const char *dw_file_name;
    Dwarf_Unsigned dw_directory_index, dw_last_mod_time, dw_file_length;
    Dwarf_Form_Data16 *dw_md5ptr;

    // Fuzz dwarf_srclines_table_offset
    dwarf_srclines_table_offset(dw_context, &dw_offset, &error);

    // Fuzz dwarf_srclines_subprog_data
    dwarf_srclines_subprog_data(dw_context, dw_index, &dw_name, &dw_decl_file, &dw_decl_line, &error);

    // Fuzz dwarf_srclines_include_dir_count
    dwarf_srclines_include_dir_count(dw_context, &dw_count, &error);

    // Fuzz dwarf_srclines_b
    dwarf_srclines_b(dw_cudie, &dw_version, &dw_table_count, &dw_context, &error);

    // Fuzz dwarf_srclines_files_data_b
    dwarf_srclines_files_data_b(dw_context, dw_index, &dw_file_name, &dw_directory_index,
                                &dw_last_mod_time, &dw_file_length, &dw_md5ptr, &error);

    // Fuzz dwarf_srclines_version
    dwarf_srclines_version(dw_context, &dw_version, &dw_table_count, &error);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
