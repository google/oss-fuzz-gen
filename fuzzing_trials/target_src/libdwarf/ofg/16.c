#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Debug)) {
        return 0; // Not enough data to cast to Dwarf_Debug
    }

    Dwarf_Debug dbg;
    memcpy(&dbg, data, sizeof(Dwarf_Debug));  // Copy data into dbg
    Dwarf_Off offset = 0;  // Initialize offset to zero
    Dwarf_Bool is_info = 1;  // Set is_info to true
    Dwarf_Die die = NULL;  // Initialize die to NULL
    Dwarf_Error error = NULL;  // Initialize error to NULL

    // Call the function-under-test
    dwarf_offdie_b(dbg, offset, is_info, &die, &error);

    // Clean up if necessary
    if (die != NULL) {
        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }
    if (error != NULL) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_16(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
