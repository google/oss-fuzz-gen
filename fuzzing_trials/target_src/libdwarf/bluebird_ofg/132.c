#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include <stdio.h>

// Include the necessary headers for DW_DLC_READ and dwarf_init
#include "dwarf.h"
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Debug)) {
        return 0; // Not enough data to form a valid Dwarf_Debug
    }

    Dwarf_Debug dbg;
    Dwarf_Error error;

    // Initialize the Dwarf_Debug object using dwarf_init
    int init_result = dwarf_init_path((char *)data, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (init_result != DW_DLV_OK) {
        return 0; // Failed to initialize Dwarf_Debug
    }

    Dwarf_Bool is_info = 1; // Non-zero value
    Dwarf_Die die;
    Dwarf_Unsigned cu_header_length;
    Dwarf_Half version_stamp;
    Dwarf_Unsigned abbrev_offset;
    Dwarf_Half address_size;
    Dwarf_Half offset_size;
    Dwarf_Half extension_size;
    Dwarf_Sig8 signature;
    Dwarf_Unsigned typeoffset;
    Dwarf_Unsigned next_cu_header_offset;
    Dwarf_Half header_cu_type;

    // Initialize Dwarf_Sig8 structure with non-zero values
    for (int i = 0; i < sizeof(signature.signature); ++i) {
        signature.signature[i] = (uint8_t)(i + 1);
    }

    // Call the function-under-test
    int result = dwarf_next_cu_header_e(dbg, is_info, &die, &cu_header_length, &version_stamp,
                                        &abbrev_offset, &address_size, &offset_size, &extension_size,
                                        &signature, &typeoffset, &next_cu_header_offset, &header_cu_type, &error);

    // Clean up
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
