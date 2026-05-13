// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_rnglists_entry_fields_a at dwarf_rnglists.c:1739:1 in libdwarf.h
// dwarf_dealloc at dwarf_alloc.c:953:1 in libdwarf.h
// dwarf_get_rnglist_rle at dwarf_rnglists.c:975:5 in libdwarf.h
// dwarf_get_rnglist_head_basics at dwarf_rnglists.c:831:5 in libdwarf.h
// dwarf_rnglists_get_rle_head at dwarf_rnglists.c:1640:1 in libdwarf.h
// dwarf_dealloc_rnglists_head at dwarf_rnglists.c:1151:1 in libdwarf.h
// dwarf_load_rnglists at dwarf_rnglists.c:673:5 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libdwarf.h>

static Dwarf_Debug create_dummy_debug() {
    return NULL; // Return NULL as we cannot create a real Dwarf_Debug
}

static Dwarf_Rnglists_Head create_dummy_rnglists_head() {
    return NULL; // Return NULL as we cannot create a real Dwarf_Rnglists_Head
}

static Dwarf_Attribute create_dummy_attribute() {
    return NULL; // Return NULL as we cannot create a real Dwarf_Attribute
}

int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) return 0;

    Dwarf_Error error = NULL;
    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Rnglists_Head rnglists_head = create_dummy_rnglists_head();
    Dwarf_Attribute attr = create_dummy_attribute();

    // Fuzz dwarf_get_rnglist_rle
    {
        Dwarf_Unsigned contextnumber = Data[0];
        Dwarf_Unsigned entry_offset = Data[1];
        Dwarf_Unsigned endoffset = Data[2];
        unsigned int entrylen = 0;
        unsigned int entry_kind = 0;
        Dwarf_Unsigned operand1 = 0;
        Dwarf_Unsigned operand2 = 0;
        
        dwarf_get_rnglist_rle(dbg, contextnumber, entry_offset, endoffset, 
                              &entrylen, &entry_kind, &operand1, &operand2, &error);
    }

    // Fuzz dwarf_get_rnglist_head_basics
    {
        Dwarf_Unsigned rle_count = 0;
        Dwarf_Unsigned rnglists_version = 0;
        Dwarf_Unsigned rnglists_index_returned = 0;
        Dwarf_Unsigned bytes_total_in_rle = 0;
        Dwarf_Half offset_size = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Half segment_selector_size = 0;
        Dwarf_Unsigned overall_offset_of_this_context = 0;
        Dwarf_Unsigned total_length_of_this_context = 0;
        Dwarf_Unsigned offset_table_offset = 0;
        Dwarf_Unsigned offset_table_entrycount = 0;
        Dwarf_Bool rnglists_base_present = 0;
        Dwarf_Unsigned rnglists_base = 0;
        Dwarf_Bool rnglists_base_address_present = 0;
        Dwarf_Unsigned rnglists_base_address = 0;
        Dwarf_Bool rnglists_debug_addr_base_present = 0;
        Dwarf_Unsigned rnglists_debug_addr_base = 0;

        dwarf_get_rnglist_head_basics(rnglists_head, &rle_count, &rnglists_version,
                                      &rnglists_index_returned, &bytes_total_in_rle,
                                      &offset_size, &address_size, &segment_selector_size,
                                      &overall_offset_of_this_context, &total_length_of_this_context,
                                      &offset_table_offset, &offset_table_entrycount,
                                      &rnglists_base_present, &rnglists_base,
                                      &rnglists_base_address_present, &rnglists_base_address,
                                      &rnglists_debug_addr_base_present, &rnglists_debug_addr_base, &error);
    }

    // Fuzz dwarf_rnglists_get_rle_head
    {
        Dwarf_Half theform = Data[3];
        Dwarf_Unsigned index_or_offset_value = Data[4];
        Dwarf_Rnglists_Head head_out = NULL;
        Dwarf_Unsigned count_of_entries_in_head = 0;
        Dwarf_Unsigned global_offset_of_rle_set = 0;

        dwarf_rnglists_get_rle_head(attr, theform, index_or_offset_value,
                                    &head_out, &count_of_entries_in_head,
                                    &global_offset_of_rle_set, &error);

        if (head_out) {
            dwarf_dealloc_rnglists_head(head_out);
        }
    }

    // Fuzz dwarf_load_rnglists
    {
        Dwarf_Unsigned rnglists_count = 0;
        dwarf_load_rnglists(dbg, &rnglists_count, &error);
    }

    // Fuzz dwarf_get_rnglists_entry_fields_a
    {
        Dwarf_Unsigned entrynum = Data[5];
        unsigned int entrylen = 0;
        unsigned int rle_value_out = 0;
        Dwarf_Unsigned raw1 = 0;
        Dwarf_Unsigned raw2 = 0;
        Dwarf_Bool debug_addr_unavailable = 0;
        Dwarf_Unsigned cooked1 = 0;
        Dwarf_Unsigned cooked2 = 0;

        dwarf_get_rnglists_entry_fields_a(rnglists_head, entrynum, &entrylen,
                                          &rle_value_out, &raw1, &raw2,
                                          &debug_addr_unavailable, &cooked1, &cooked2, &error);
    }

    if (error) dwarf_dealloc(dbg, error, DW_DLA_ERROR);

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

        LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    