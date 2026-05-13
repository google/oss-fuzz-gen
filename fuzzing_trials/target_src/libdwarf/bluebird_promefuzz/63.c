#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

#define DW_DLV_OK 0
#define DW_DLV_ERROR -1
#define DW_DLV_NO_ENTRY -2

static Dwarf_Debug create_dummy_dwarf_debug() {
    return NULL; // Return NULL as we cannot instantiate Dwarf_Debug
}

static void destroy_dummy_dwarf_debug(Dwarf_Debug dbg) {
    // No operation needed as we do not allocate Dwarf_Debug
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    // Fuzz dwarf_set_default_address_size
    if (Size > 0) {
        Dwarf_Debug dbg = create_dummy_dwarf_debug();
        if (dbg) {
            Dwarf_Small address_size = Data[0];
            dwarf_set_default_address_size(dbg, address_size);
            destroy_dummy_dwarf_debug(dbg);
        }
    }

    // Fuzz dwarf_get_mmap_count
    if (Size > 1) {
        Dwarf_Debug dbg = create_dummy_dwarf_debug();
        if (dbg) {
            Dwarf_Unsigned mmap_count = 0, mmap_size = 0;
            Dwarf_Unsigned malloc_count = 0, malloc_size = 0;
            dwarf_get_mmap_count(dbg, &mmap_count, &mmap_size, &malloc_count, &malloc_size);
            destroy_dummy_dwarf_debug(dbg);
        }
    }

    // Fuzz dwarf_dnames_offsets
    if (Size > 2) {
        Dwarf_Dnames_Head dnames_head = NULL; // Cannot instantiate directly
        Dwarf_Unsigned header_offset, cu_table_offset;
        Dwarf_Unsigned tu_local_offset, foreign_tu_offset;
        Dwarf_Unsigned bucket_offset, hashes_offset;
        Dwarf_Unsigned stringoffsets_offset, entryoffsets_offset;
        Dwarf_Unsigned abbrev_table_offset, entry_pool_offset;
        Dwarf_Error error;
        dwarf_dnames_offsets(dnames_head, &header_offset, &cu_table_offset,
                             &tu_local_offset, &foreign_tu_offset, &bucket_offset,
                             &hashes_offset, &stringoffsets_offset, &entryoffsets_offset,
                             &abbrev_table_offset, &entry_pool_offset, &error);
    }

    // Fuzz dwarf_get_rnglist_offset_index_value
    if (Size > 3) {
        Dwarf_Debug dbg = create_dummy_dwarf_debug();
        if (dbg) {
            Dwarf_Unsigned context_index = Data[1];
            Dwarf_Unsigned offsetentry_index = Data[2];
            Dwarf_Unsigned offset_value_out, global_offset_value_out;
            Dwarf_Error error;
            dwarf_get_rnglist_offset_index_value(dbg, context_index, offsetentry_index,
                                                 &offset_value_out, &global_offset_value_out, &error);
            destroy_dummy_dwarf_debug(dbg);
        }
    }

    // Fuzz dwarf_get_rnglist_context_basics
    if (Size > 4) {
        Dwarf_Debug dbg = create_dummy_dwarf_debug();
        if (dbg) {
            Dwarf_Unsigned index = Data[3];
            Dwarf_Unsigned header_offset, offset_entry_count;
            Dwarf_Unsigned offset_of_offset_array, offset_of_first_rangeentry;
            Dwarf_Unsigned offset_past_last_rangeentry;
            Dwarf_Small offset_size, extension_size, address_size, segment_selector_size;
            unsigned int version;
            Dwarf_Error error;
            dwarf_get_rnglist_context_basics(dbg, index, &header_offset, &offset_size,
                                             &extension_size, &version, &address_size,
                                             &segment_selector_size, &offset_entry_count,
                                             &offset_of_offset_array, &offset_of_first_rangeentry,
                                             &offset_past_last_rangeentry, &error);
            destroy_dummy_dwarf_debug(dbg);
        }
    }

    // Fuzz dwarf_object_detector_path_dSYM
    if (Size > 5) {
        char input_path[256];
        char output_path[256];
        strncpy(input_path, (const char *)Data, Size < 255 ? Size : 255);
        input_path[Size < 255 ? Size : 255] = '\0';
        unsigned int ftype, endian, offsetsize;
        Dwarf_Unsigned filesize;
        unsigned char pathsource;
        int errcode;
        dwarf_object_detector_path_dSYM(input_path, output_path, sizeof(output_path), NULL, 0,
                                        &ftype, &endian, &offsetsize, &filesize, &pathsource, &errcode);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
