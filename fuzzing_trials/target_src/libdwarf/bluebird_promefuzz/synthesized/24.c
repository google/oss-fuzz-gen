#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"

// Define a dummy struct to allocate memory for Dwarf_Gdbindex
struct Dummy_Dwarf_Gdbindex_s {
    Dwarf_Debug gi_dbg;
    Dwarf_Small *gi_section_data;
    Dwarf_Unsigned gi_section_length;
    Dwarf_Unsigned gi_version;
    Dwarf_Unsigned gi_cu_list_offset;
    Dwarf_Unsigned gi_types_cu_list_offset;
    Dwarf_Unsigned gi_address_area_offset;
    Dwarf_Unsigned gi_symbol_table_offset;
    Dwarf_Unsigned gi_constant_pool_offset;
    // Use pointers for the incomplete type
    struct Dwarf_Gdbindex_array_instance_s *gi_culisthdr;
    struct Dwarf_Gdbindex_array_instance_s *gi_typesculisthdr;
    struct Dwarf_Gdbindex_array_instance_s *gi_addressareahdr;
    struct Dwarf_Gdbindex_array_instance_s *gi_symboltablehdr;
    struct Dwarf_Gdbindex_array_instance_s *gi_cuvectorhdr;
};

static Dwarf_Gdbindex create_dummy_gdbindex() {
    struct Dummy_Dwarf_Gdbindex_s *dummy_index = (struct Dummy_Dwarf_Gdbindex_s *)malloc(sizeof(struct Dummy_Dwarf_Gdbindex_s));
    if (!dummy_index) return NULL;
    memset(dummy_index, 0, sizeof(struct Dummy_Dwarf_Gdbindex_s));
    return (Dwarf_Gdbindex)dummy_index;
}

static void cleanup_gdbindex(Dwarf_Gdbindex gdbindex) {
    if (gdbindex) {
        free(gdbindex);
    }
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) return 0;

    Dwarf_Gdbindex gdbindex = create_dummy_gdbindex();
    if (!gdbindex) return 0;

    Dwarf_Unsigned list_length = 0;
    Dwarf_Error error = NULL;

    // Fuzz dwarf_gdbindex_addressarea
    dwarf_gdbindex_addressarea(gdbindex, &list_length, &error);

    // Fuzz dwarf_gdbindex_types_culist_array
    dwarf_gdbindex_types_culist_array(gdbindex, &list_length, &error);

    // Use a portion of Data as an index for fuzzing
    Dwarf_Unsigned entry_index = *(Dwarf_Unsigned *)Data;

    // Fuzz dwarf_gdbindex_symboltable_entry
    Dwarf_Unsigned string_offset = 0, cu_vector_offset = 0;
    dwarf_gdbindex_symboltable_entry(gdbindex, entry_index, &string_offset, &cu_vector_offset, &error);

    // Fuzz dwarf_gdbindex_cuvector_instance_expand_value
    Dwarf_Unsigned field_value = *(Dwarf_Unsigned *)Data;
    Dwarf_Unsigned cu_index = 0, symbol_kind = 0, is_static = 0;
    dwarf_gdbindex_cuvector_instance_expand_value(gdbindex, field_value, &cu_index, &symbol_kind, &is_static, &error);

    // Fuzz dwarf_gdbindex_symboltable_array
    dwarf_gdbindex_symboltable_array(gdbindex, &list_length, &error);

    // Fuzz dwarf_gdbindex_culist_array
    dwarf_gdbindex_culist_array(gdbindex, &list_length, &error);

    cleanup_gdbindex(gdbindex);
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
