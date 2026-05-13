#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Sig8)) {
        return 0;
    }

    Dwarf_Debug dbg = (Dwarf_Debug)data; // Assuming data can be cast to Dwarf_Debug
    Dwarf_Bool is_info = 1; // Non-zero value for true
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half offset_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 signature;
    Dwarf_Unsigned type_offset = 0;
    Dwarf_Unsigned next_cu_header_offset = 0;
    Dwarf_Half header_cu_type = 0;
    Dwarf_Error error = NULL;

    // Copy signature from data
    memcpy(&signature, data, sizeof(Dwarf_Sig8));

    int result = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &offset_size, &extension_size, &signature, &type_offset, &next_cu_header_offset, &header_cu_type, &error);

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

    LLVMFuzzerTestOneInput_187(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
