#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

extern int dwarf_get_fde_info_for_reg3_b(Dwarf_Fde, Dwarf_Half, Dwarf_Addr, Dwarf_Small *, Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Block *, Dwarf_Addr *, Dwarf_Bool *, Dwarf_Addr *, Dwarf_Error *);

int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure there's enough data to read from
    if (size < sizeof(Dwarf_Half) + sizeof(Dwarf_Addr)) {
        return 0;
    }

    // Initialize variables
    Dwarf_Fde fde = (Dwarf_Fde)(uintptr_t)data; // Cast data to a pointer type
    Dwarf_Half reg = *((Dwarf_Half *)data); // Read a Dwarf_Half from data
    Dwarf_Addr pc = *((Dwarf_Addr *)(data + sizeof(Dwarf_Half))); // Read a Dwarf_Addr from data

    Dwarf_Small value_type = 0;
    Dwarf_Unsigned offset_relevant = 0;
    Dwarf_Unsigned register_num = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Block block = {0};
    Dwarf_Addr row_pc = 0;
    Dwarf_Bool has_more_rows = 0;
    Dwarf_Addr subsequent_pc = 0;
    Dwarf_Error error = 0;

    // Call the function-under-test
    dwarf_get_fde_info_for_reg3_b(fde, reg, pc, &value_type, &offset_relevant, &register_num, &offset, &block, &row_pc, &has_more_rows, &subsequent_pc, &error);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_240(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
