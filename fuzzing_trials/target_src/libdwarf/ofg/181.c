#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Debug) * 2) {
        return 0; // Ensure there is enough data for two Dwarf_Debug objects
    }

    Dwarf_Debug dbg1 = (Dwarf_Debug)data; // Cast the data to Dwarf_Debug for fuzzing
    Dwarf_Debug dbg2 = (Dwarf_Debug)(data + size/2); // Use another part of data for the second Dwarf_Debug
    Dwarf_Error error = NULL; // Initialize the Dwarf_Error pointer

    // Call the function-under-test
    dwarf_set_tied_dbg(dbg1, dbg2, &error);

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

    LLVMFuzzerTestOneInput_181(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
