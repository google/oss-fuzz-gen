#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Ensure data is not null and size is sufficient for a valid Dwarf_Debug
    if (data == NULL || size < sizeof(Dwarf_Debug)) {
        return 0;
    }

    Dwarf_Debug dbg = (Dwarf_Debug)data; // Casting data to Dwarf_Debug for testing

    // Call the function-under-test
    Dwarf_Unsigned section_count = dwarf_get_section_count(dbg);

    // Use the result in some way to prevent optimizations from removing the call
    if (section_count == 0) {
        // Do something if section_count is zero, e.g., print a debug message
        // (In actual fuzzing, this could be logged or used for further analysis)
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

    LLVMFuzzerTestOneInput_144(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
