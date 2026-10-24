#include <stdint.h>
#include <stddef.h>
#include <dwarf.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Unsigned) * 4 + sizeof(unsigned int) * 2) {
        return 0;
    }

    Dwarf_Debug dbg = (Dwarf_Debug)data; // Assuming data can be cast to Dwarf_Debug for fuzzing
    Dwarf_Unsigned offset = *(Dwarf_Unsigned *)(data);
    Dwarf_Unsigned base = *(Dwarf_Unsigned *)(data + sizeof(Dwarf_Unsigned));
    Dwarf_Unsigned length = *(Dwarf_Unsigned *)(data + 2 * sizeof(Dwarf_Unsigned));
    Dwarf_Unsigned version = *(Dwarf_Unsigned *)(data + 3 * sizeof(Dwarf_Unsigned));

    unsigned int index = *(unsigned int *)(data + 4 * sizeof(Dwarf_Unsigned));
    unsigned int entry_count = *(unsigned int *)(data + 4 * sizeof(Dwarf_Unsigned) + sizeof(unsigned int));

    Dwarf_Unsigned offset_out = 0;
    Dwarf_Unsigned base_out = 0;
    Dwarf_Unsigned length_out = 0;
    Dwarf_Unsigned version_out = 0;

    Dwarf_Small *loclist = NULL;
    Dwarf_Error error = NULL;

    dwarf_get_loclist_lle(dbg, offset, base, length, &index, &entry_count, &offset_out, &base_out, &length_out, &version_out, &loclist, &error);

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

    LLVMFuzzerTestOneInput_153(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
