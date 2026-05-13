// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_meta_add_item_ref at meta.c:2005:8 in isomedia.h
// gf_isom_modify_alternate_brand at isom_write.c:3571:8 in isomedia.h
// gf_isom_meta_get_next_item_id at meta.c:1399:8 in isomedia.h
// gf_isom_apply_box_patch at isom_write.c:8665:8 in isomedia.h
// gf_isom_set_track_priority_in_group at isom_write.c:5884:8 in isomedia.h
// gf_isom_update_aperture_info at isom_write.c:2179:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;

    // Write data to the dummy file to ensure it's not empty
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isoFile) return 0;

    // Fuzz gf_isom_meta_add_item_ref
    {
        Bool root_meta = Data[0] % 2;
        u32 track_num = Size > 1 ? Data[1] : 0;
        u32 from_id = Size > 2 ? Data[2] : 0;
        u32 to_id = Size > 3 ? Data[3] : 0;
        u32 type = Size > 4 ? Data[4] : 0;
        u64 ref_index = 0;

        gf_isom_meta_add_item_ref(isoFile, root_meta, track_num, from_id, to_id, type, &ref_index);
    }

    // Fuzz gf_isom_modify_alternate_brand
    {
        u32 Brand = Size > 5 ? Data[5] : 0;
        Bool AddIt = Size > 6 ? Data[6] % 2 : 0;

        gf_isom_modify_alternate_brand(isoFile, Brand, AddIt);
    }

    // Fuzz gf_isom_meta_get_next_item_id
    {
        Bool root_meta = Size > 7 ? Data[7] % 2 : 0;
        u32 track_num = Size > 8 ? Data[8] : 0;
        u32 item_id = 0;

        gf_isom_meta_get_next_item_id(isoFile, root_meta, track_num, &item_id);
    }

    // Fuzz gf_isom_apply_box_patch
    {
        GF_ISOTrackID trackID = Size > 9 ? Data[9] : 0;
        const char *box_patch_filename = "./dummy_file";
        Bool for_fragments = Size > 10 ? Data[10] % 2 : 0;

        gf_isom_apply_box_patch(isoFile, trackID, box_patch_filename, for_fragments);
    }

    // Fuzz gf_isom_set_track_priority_in_group
    {
        u32 trackNumber = Size > 11 ? Data[11] : 0;
        u32 InversePriority = Size > 12 ? Data[12] : 0;

        gf_isom_set_track_priority_in_group(isoFile, trackNumber, InversePriority);
    }

    // Fuzz gf_isom_update_aperture_info
    {
        u32 trackNumber = Size > 13 ? Data[13] : 0;
        Bool remove = Size > 14 ? Data[14] % 2 : 0;

        gf_isom_update_aperture_info(isoFile, trackNumber, remove);
    }

    cleanup_iso_file(isoFile);
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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    