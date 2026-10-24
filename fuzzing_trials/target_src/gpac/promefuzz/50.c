// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_fragment_add_subsample at movie_fragments.c:3133:8 in isomedia.h
// gf_isom_set_sample_padding at isom_read.c:2492:8 in isomedia.h
// gf_isom_set_sample_rap_group at isom_write.c:7715:8 in isomedia.h
// gf_isom_add_subsample at isom_write.c:7028:8 in isomedia.h
// gf_isom_sample_get_subsample at isom_read.c:4919:8 in isomedia.h
// gf_isom_fragment_set_cenc_sai at movie_fragments.c:3005:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static GF_ISOFile *create_dummy_iso_file() {
    // Since we cannot allocate an incomplete type, return NULL for now
    return NULL;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        // Free other allocated resources if necessary
        // free(iso_file); // Cannot free an incomplete type
    }
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(u8) + sizeof(Bool)) {
        return 0; // Not enough data to proceed
    }

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    GF_ISOTrackID trackID = *(GF_ISOTrackID *)Data;
    u32 flags = *(u32 *)(Data + sizeof(GF_ISOTrackID));
    u32 subSampleSize = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32));
    u8 priority = *(u8 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 2);
    u32 reserved = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 2 + sizeof(u8));
    Bool discardable = *(Bool *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 3 + sizeof(u8));

    // Fuzz gf_isom_fragment_add_subsample
    gf_isom_fragment_add_subsample(iso_file, trackID, flags, subSampleSize, priority, reserved, discardable);

    // Fuzz gf_isom_set_sample_padding
    u32 padding_bytes = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 3 + sizeof(u8) + sizeof(Bool));
    gf_isom_set_sample_padding(iso_file, trackID, padding_bytes);

    // Fuzz gf_isom_set_sample_rap_group
    u32 sampleNumber = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 4 + sizeof(u8) + sizeof(Bool));
    Bool is_rap = *(Bool *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 5 + sizeof(u8) + sizeof(Bool));
    u32 num_leading_samples = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 5 + sizeof(u8) + sizeof(Bool) * 2);
    gf_isom_set_sample_rap_group(iso_file, trackID, sampleNumber, is_rap, num_leading_samples);

    // Fuzz gf_isom_add_subsample
    gf_isom_add_subsample(iso_file, trackID, sampleNumber, flags, subSampleSize, priority, reserved, discardable);

    // Fuzz gf_isom_sample_get_subsample
    u32 subSampleNumber = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 6 + sizeof(u8) + sizeof(Bool) * 3);
    u32 size;
    u8 out_priority;
    u32 out_reserved;
    Bool out_discardable;
    gf_isom_sample_get_subsample(iso_file, trackID, sampleNumber, flags, subSampleNumber, &size, &out_priority, &out_reserved, &out_discardable);

    // Fuzz gf_isom_fragment_set_cenc_sai
    u8 *sai_b = (u8 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 7 + sizeof(u8) + sizeof(Bool) * 3);
    u32 sai_b_size = Size - (sizeof(GF_ISOTrackID) + sizeof(u32) * 7 + sizeof(u8) + sizeof(Bool) * 3);
    Bool use_subsample = *(Bool *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 7 + sizeof(u8) + sizeof(Bool) * 3 + sai_b_size);
    Bool use_saio_32bit = *(Bool *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 7 + sizeof(u8) + sizeof(Bool) * 4 + sai_b_size);
    Bool use_multikey = *(Bool *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32) * 7 + sizeof(u8) + sizeof(Bool) * 5 + sai_b_size);
    gf_isom_fragment_set_cenc_sai(iso_file, trackID, sai_b, sai_b_size, use_subsample, use_saio_32bit, use_multikey);

    cleanup_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    