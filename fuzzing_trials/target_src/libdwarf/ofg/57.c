#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Initialize a Dwarf_Debug object
    Dwarf_Debug dbg = 0;
    Dwarf_Error err = 0;
    Dwarf_Handler errhand = 0;
    Dwarf_Ptr errarg = 0;

    // Initialize the Dwarf_Debug object using the input data
    int res = dwarf_init_path("/dev/null", 0, 0, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &err);
    if (res != DW_DLV_OK) {
        return 0;
    }

    // Create a Dwarf_Die object
    Dwarf_Die die = 0;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Off abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half length_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 type_signature;
    Dwarf_Unsigned typeoffset = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Half header_cu_type = 0;

    // Read the compilation unit header
    res = dwarf_next_cu_header_d(dbg, 1, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header, &header_cu_type, &err);
    if (res != DW_DLV_OK) {
        dwarf_finish(dbg);
        return 0;
    }

    // Get the DIE (Debugging Information Entry)
    res = dwarf_siblingof_b(dbg, 0, 1, &die, &err);
    if (res != DW_DLV_OK) {
        dwarf_finish(dbg);
        return 0;
    }

    // Call the function-under-test
    Dwarf_Bool flag = dwarf_get_die_infotypes_flag(die);

    // Clean up
    dwarf_dealloc(dbg, die, DW_DLA_DIE);
    dwarf_finish(dbg);

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

    LLVMFuzzerTestOneInput_57(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
