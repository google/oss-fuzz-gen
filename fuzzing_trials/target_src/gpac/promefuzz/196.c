// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_meta_item_has_ref at meta.c:2203:5 in isomedia.h
// gf_isom_get_meta_item_count at meta.c:123:5 in isomedia.h
// gf_isom_get_meta_item_by_id at meta.c:219:5 in isomedia.h
// gf_isom_get_meta_primary_item_id at meta.c:600:5 in isomedia.h
// gf_isom_meta_get_item_ref_id at meta.c:2226:5 in isomedia.h
// gf_isom_meta_get_item_ref_count at meta.c:2185:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate memory for GF_ISOFile using a known size or specific function if available
    GF_ISOFile* isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void destroy_dummy_iso_file(GF_ISOFile* isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_196(const uint8_t *Data, size_t Size) {
    if (Size < 20) return 0; // Ensure there's enough data for all parameters

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    // Extract parameters from input data
    Bool root_meta = Data[0] % 2; // Convert to Bool (0 or 1)
    u32 track_num = *((u32*)(Data + 1));
    u32 to_id = *((u32*)(Data + 5));
    u32 type = *((u32*)(Data + 9));
    u32 item_ID = *((u32*)(Data + 13));

    // Call each function with extracted parameters
    u32 ref_count = gf_isom_meta_item_has_ref(iso_file, root_meta, track_num, to_id, type);
    u32 item_count = gf_isom_get_meta_item_count(iso_file, root_meta, track_num);
    u32 item_index = gf_isom_get_meta_item_by_id(iso_file, root_meta, track_num, item_ID);
    u32 primary_item_id = gf_isom_get_meta_primary_item_id(iso_file, root_meta, track_num);
    u32 ref_id = gf_isom_meta_get_item_ref_id(iso_file, root_meta, track_num, to_id, type, 1);
    u32 ref_item_count = gf_isom_meta_get_item_ref_count(iso_file, root_meta, track_num, to_id, type);

    // Print the results (for debug purposes, can be removed in production)
    printf("Ref Count: %u, Item Count: %u, Item Index: %u, Primary Item ID: %u, Ref ID: %u, Ref Item Count: %u\n",
           ref_count, item_count, item_index, primary_item_id, ref_id, ref_item_count);

    destroy_dummy_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_196(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    