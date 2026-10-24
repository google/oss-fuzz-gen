#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create Dwarf_Debug and Dwarf_Error
    if (size < sizeof(Dwarf_Debug) + sizeof(Dwarf_Error)) {
        return 0;
    }

    // Initialize Dwarf_Debug and Dwarf_Error
    Dwarf_Debug dbg = (Dwarf_Debug)(uintptr_t)data; // Cast data to Dwarf_Debug for fuzzing
    Dwarf_Error err = (Dwarf_Error)(uintptr_t)(data + sizeof(Dwarf_Debug)); // Cast data+sizeof(Dwarf_Debug) to Dwarf_Error for fuzzing

    // Call the function-under-test
    dwarf_dealloc_error(dbg, err);

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

    LLVMFuzzerTestOneInput_20(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
