// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_fragment_reference_time at movie_fragments.c:2552:8 in isomedia.h
// gf_isom_get_last_producer_time_box at isom_read.c:5800:6 in isomedia.h
// gf_isom_close_segment at movie_fragments.c:1743:8 in isomedia.h
// gf_isom_get_media_time at isom_read.c:1342:8 in isomedia.h
// gf_isom_segment_get_fragment_size at isom_read.c:927:5 in isomedia.h
// gf_isom_get_omadrm_info at drm_sample.c:296:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return NULL; // Return NULL to simulate an uninitialized or dummy ISO file
}

static void destroy_dummy_iso_file(GF_ISOFile *iso_file) {
    // No operation needed as we are not allocating any memory for the dummy
}

int LLVMFuzzerTestOneInput_269(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 6 + sizeof(u64) * 5 + sizeof(Bool) * 6) {
        return 0;
    }

    GF_ISOFile *iso_file = create_dummy_iso_file();

    u32 reference_track_ID = *(u32 *)Data;
    Data += sizeof(u32);
    u64 ntp = *(u64 *)Data;
    Data += sizeof(u64);
    u64 timestamp = *(u64 *)Data;
    Data += sizeof(u64);
    Bool at_mux = *(Bool *)Data;
    Data += sizeof(Bool);

    gf_isom_set_fragment_reference_time(iso_file, reference_track_ID, ntp, timestamp, at_mux);

    u32 refTrackID;
    u64 retrieved_ntp;
    u64 retrieved_timestamp;
    Bool reset_info = *(Bool *)Data;
    Data += sizeof(Bool);
    gf_isom_get_last_producer_time_box(iso_file, &refTrackID, &retrieved_ntp, &retrieved_timestamp, reset_info);

    s32 subsegs_per_sidx = *(s32 *)Data;
    Data += sizeof(s32);
    u64 ref_track_decode_time = *(u64 *)Data;
    Data += sizeof(u64);
    s32 timestamp_shift = *(s32 *)Data;
    Data += sizeof(s32);
    u64 ref_track_next_cts = *(u64 *)Data;
    Data += sizeof(u64);
    Bool daisy_chain_sidx = *(Bool *)Data;
    Data += sizeof(Bool);
    Bool use_ssix = *(Bool *)Data;
    Data += sizeof(Bool);
    Bool last_segment = *(Bool *)Data;
    Data += sizeof(Bool);
    Bool close_segment_handle = *(Bool *)Data;
    Data += sizeof(Bool);
    u32 segment_marker_4cc = *(u32 *)Data;
    Data += sizeof(u32);
    u64 index_start_range;
    u64 index_end_range;
    u64 out_seg_size;

    gf_isom_close_segment(iso_file, subsegs_per_sidx, reference_track_ID, ref_track_decode_time, timestamp_shift,
                          ref_track_next_cts, daisy_chain_sidx, use_ssix, last_segment, close_segment_handle,
                          segment_marker_4cc, &index_start_range, &index_end_range, &out_seg_size);

    u32 trackNumber = *(u32 *)Data;
    Data += sizeof(u32);
    u32 movieTime = *(u32 *)Data;
    Data += sizeof(u32);
    u64 mediaTime;

    gf_isom_get_media_time(iso_file, trackNumber, movieTime, &mediaTime);

    u32 moof_index = *(u32 *)Data;
    Data += sizeof(u32);
    u32 moof_size;

    gf_isom_segment_get_fragment_size(iso_file, moof_index, &moof_size);

    u32 sampleDescriptionIndex = *(u32 *)Data;
    Data += sizeof(u32);
    u32 outOriginalFormat;
    u32 outSchemeType;
    u32 outSchemeVersion;
    const char *outContentID;
    const char *outRightsIssuerURL;
    const char *outTextualHeaders;
    u32 outTextualHeadersLen;
    u64 outPlaintextLength;
    u32 outEncryptionType;
    Bool outSelectiveEncryption;
    u32 outIVLength;
    u32 outKeyIndicationLength;

    gf_isom_get_omadrm_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType,
                            &outSchemeVersion, &outContentID, &outRightsIssuerURL, &outTextualHeaders,
                            &outTextualHeadersLen, &outPlaintextLength, &outEncryptionType, &outSelectiveEncryption,
                            &outIVLength, &outKeyIndicationLength);

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

        LLVMFuzzerTestOneInput_269(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    