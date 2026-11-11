#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Debug)) {
        return 0; // Not enough data to form a valid Dwarf_Debug
    }

    Dwarf_Debug dbg = (Dwarf_Debug)data; // Type casting data to Dwarf_Debug
    Dwarf_Off offset = 0; // Initialize offset
    Dwarf_Bool is_info = 1; // Initialize is_info to a non-zero value
    Dwarf_Die die = NULL; // Initialize Dwarf_Die
    Dwarf_Error error = NULL; // Initialize Dwarf_Error

    // Call the function-under-test
    int result = dwarf_offdie_b(dbg, offset, is_info, &die, &error);

    // Clean up if needed
    if (die != NULL) {
        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }
    if (error != NULL) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_17(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
