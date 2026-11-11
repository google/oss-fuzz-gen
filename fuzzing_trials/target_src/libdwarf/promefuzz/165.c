// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_gdbindex_addressarea at dwarf_gdbindex.c:522:1 in libdwarf.h
// dwarf_gdbindex_culist_entry at dwarf_gdbindex.c:389:1 in libdwarf.h
// dwarf_gdbindex_types_culist_array at dwarf_gdbindex.c:444:1 in libdwarf.h
// dwarf_gdbindex_cuvector_length at dwarf_gdbindex.c:676:1 in libdwarf.h
// dwarf_gdbindex_symboltable_entry at dwarf_gdbindex.c:622:1 in libdwarf.h
// dwarf_dealloc_gdbindex at dwarf_gdbindex.c:849:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_165(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    // Create a dummy Dwarf_Gdbindex
    Dwarf_Gdbindex gdbindex = NULL;
    Dwarf_Error error = NULL;
    Dwarf_Unsigned address_area_length = 0;
    Dwarf_Unsigned cu_offset = 0;
    Dwarf_Unsigned cu_length = 0;
    Dwarf_Unsigned types_list_length = 0;
    Dwarf_Unsigned inner_count = 0;
    Dwarf_Unsigned string_offset = 0;
    Dwarf_Unsigned cu_vector_offset = 0;

    // Fuzz dwarf_gdbindex_addressarea
    dwarf_gdbindex_addressarea(gdbindex, &address_area_length, &error);

    // Fuzz dwarf_gdbindex_culist_entry
    if (Size >= sizeof(Dwarf_Unsigned) * 2) {
        Dwarf_Unsigned entry_index = *(Dwarf_Unsigned *)Data;
        dwarf_gdbindex_culist_entry(gdbindex, entry_index, &cu_offset, &cu_length, &error);
    }

    // Fuzz dwarf_gdbindex_types_culist_array
    dwarf_gdbindex_types_culist_array(gdbindex, &types_list_length, &error);

    // Fuzz dwarf_gdbindex_cuvector_length
    if (Size >= sizeof(Dwarf_Unsigned) * 3) {
        Dwarf_Unsigned cuvector_offset = *(Dwarf_Unsigned *)(Data + sizeof(Dwarf_Unsigned));
        dwarf_gdbindex_cuvector_length(gdbindex, cuvector_offset, &inner_count, &error);
    }

    // Fuzz dwarf_gdbindex_symboltable_entry
    if (Size >= sizeof(Dwarf_Unsigned) * 4) {
        Dwarf_Unsigned entry_index = *(Dwarf_Unsigned *)(Data + sizeof(Dwarf_Unsigned) * 2);
        dwarf_gdbindex_symboltable_entry(gdbindex, entry_index, &string_offset, &cu_vector_offset, &error);
    }

    // Cleanup
    if (gdbindex) {
        dwarf_dealloc_gdbindex(gdbindex);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_165(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    