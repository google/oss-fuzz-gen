#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    Dwarf_Debug dbg = 0;
    Dwarf_Gnu_Index_Head head = 0;
    Dwarf_Error error = 0;
    Dwarf_Unsigned version = 0, cu_list_offset = 0, types_cu_list_offset = 0;
    Dwarf_Unsigned address_area_offset = 0, symbol_table_offset = 0, constant_pool_offset = 0;
    Dwarf_Unsigned section_size = 0;
    const char *section_name = 0;
    Dwarf_Gdbindex gdbindex = 0;

    dwarf_gdbindex_header(dbg, &gdbindex, &version, &cu_list_offset,
                          &types_cu_list_offset, &address_area_offset,
                          &symbol_table_offset, &constant_pool_offset,
                          &section_size, &section_name, &error);

    Dwarf_Unsigned block_count = 0;
    dwarf_get_gnu_index_head(dbg, Data[0] % 2, &head, &block_count, &error);

    Dwarf_Unsigned block_length = 0, offset_into_debug_info = 0, size_of_debug_info_area = 0;
    Dwarf_Unsigned count_of_index_entries = 0;
    Dwarf_Half block_version = 0;

    dwarf_get_gnu_index_block(head, Data[0] % (block_count + 1), &block_length,
                              &block_version, &offset_into_debug_info,
                              &size_of_debug_info_area, &count_of_index_entries, &error);

    Dwarf_Unsigned offset_in_debug_info = 0;
    const char *name_string = 0;
    unsigned char flagbyte = 0, staticorglobal = 0, typeofentry = 0;

    dwarf_get_gnu_index_block_entry(head, Data[0] % (block_count + 1), Data[0] % (count_of_index_entries + 1),
                                    &offset_in_debug_info, &name_string,
                                    &flagbyte, &staticorglobal, &typeofentry, &error);

    if (error) {
        dwarf_errno(error);
    }

    if (head) {
        dwarf_gnu_index_dealloc(head);
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
