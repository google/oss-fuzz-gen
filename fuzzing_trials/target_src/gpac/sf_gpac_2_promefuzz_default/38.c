// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_meta_add_item_ref at meta.c:2005:8 in isomedia.h
// gf_isom_reset_data_offset_38 at isom_read.c:3151:8 in isomedia.h
// gf_isom_sdp_clean_track at hint_track.c:790:8 in isomedia.h
// gf_isom_remove_track_references at isom_write.c:5155:8 in isomedia.h
// gf_isom_get_edit at isom_read.c:2560:8 in isomedia.h
// gf_isom_remove_track_from_root_od at isom_write.c:179:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

static void fuzz_gf_isom_meta_add_item_ref(GF_ISOFile *file) {
    u32 from_id = rand();
    u32 to_id = rand();
    u32 type = rand();
    u64 ref_index = 0;
    gf_isom_meta_add_item_ref(file, GF_TRUE, 0, from_id, to_id, type, &ref_index);
}

static void fuzz_gf_isom_reset_data_offset_38(GF_ISOFile *file) {
    u64 top_box_start = 0;
    gf_isom_reset_data_offset(file, &top_box_start);
}

static void fuzz_gf_isom_sdp_clean_track(GF_ISOFile *file) {
    u32 trackNumber = rand();
    gf_isom_sdp_clean_track(file, trackNumber);
}

static void fuzz_gf_isom_remove_track_references(GF_ISOFile *file) {
    u32 trackNumber = rand();
    gf_isom_remove_track_references(file, trackNumber);
}

static void fuzz_gf_isom_get_edit(GF_ISOFile *file) {
    u32 trackNumber = rand();
    u32 EditIndex = rand();
    u64 EditTime = 0, SegmentDuration = 0, MediaTime = 0;
    GF_ISOEditType EditMode;
    gf_isom_get_edit(file, trackNumber, EditIndex, &EditTime, &SegmentDuration, &MediaTime, &EditMode);
}

static void fuzz_gf_isom_remove_track_from_root_od(GF_ISOFile *file) {
    u32 trackNumber = rand();
    gf_isom_remove_track_from_root_od(file, trackNumber);
}

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    GF_ISOFile *file = create_dummy_iso_file();
    if (!file) return 0;

    fuzz_gf_isom_meta_add_item_ref(file);
    fuzz_gf_isom_reset_data_offset_38(file);
    fuzz_gf_isom_sdp_clean_track(file);
    fuzz_gf_isom_remove_track_references(file);
    fuzz_gf_isom_get_edit(file);
    fuzz_gf_isom_remove_track_from_root_od(file);

    cleanup_iso_file(file);
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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    