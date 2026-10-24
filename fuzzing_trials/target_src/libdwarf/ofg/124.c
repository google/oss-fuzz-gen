#include <stdint.h>
#include <stddef.h>
#include <dwarf.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg = (Dwarf_Debug)data; // Casting data to Dwarf_Debug for fuzzing
    Dwarf_Cie cie = (Dwarf_Cie)(data + sizeof(Dwarf_Debug)); // Offset for Dwarf_Cie
    Dwarf_Off offset = 0;
    Dwarf_Error error = NULL;

    // Ensure size is sufficient for both Dwarf_Debug and Dwarf_Cie
    if (size < sizeof(Dwarf_Debug) + sizeof(Dwarf_Cie)) {
        return 0;
    }

    // Call the function-under-test
    int result = dwarf_cie_section_offset(dbg, cie, &offset, &error);

    // Optionally handle the result or error
    if (result != DW_DLV_OK) {
        // Handle error if necessary
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

    LLVMFuzzerTestOneInput_124(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
