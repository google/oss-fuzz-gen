#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_158(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(GF_ISOTrackID)) return 0;

    GF_ISOFile *isom_file = NULL;
    GF_ISOTrackID trackID = *((GF_ISOTrackID *)Data);
    u64 ntp = 0, timestamp = 0, mediaTime = 0, ref_track_decode_time = 0, ref_track_next_cts = 0;
    Bool at_mux = true, reset_info = true, daisy_chain_sidx = true, use_ssix = true, last_segment = true, close_segment_handle = true;
    u32 segment_marker_4cc = 0, trackNumber = 1, movieTime = 0, moof_index = 1;
    s32 subsegs_per_sidx = 1, timestamp_shift = 0;
    u64 index_start_range = 0, index_end_range = 0, out_seg_size = 0;
    u32 outOriginalFormat = 0, outSchemeType = 0, outSchemeVersion = 0, outTextualHeadersLen = 0, outEncryptionType = 0, outIVLength = 0, outKeyIndicationLength = 0;
    const char *outContentID = NULL, *outRightsIssuerURL = NULL, *outTextualHeaders = NULL;
    u64 outPlaintextLength = 0;
    Bool outSelectiveEncryption = false;

    prepare_dummy_file(Data, Size);

    gf_isom_set_fragment_reference_time(isom_file, trackID, ntp, timestamp, at_mux);
    gf_isom_get_last_producer_time_box(isom_file, &trackID, &ntp, &timestamp, reset_info);
    gf_isom_close_segment(isom_file, subsegs_per_sidx, trackID, ref_track_decode_time, timestamp_shift, ref_track_next_cts, daisy_chain_sidx, use_ssix, last_segment, close_segment_handle, segment_marker_4cc, &index_start_range, &index_end_range, &out_seg_size);
    gf_isom_get_media_time(isom_file, trackNumber, movieTime, &mediaTime);
    gf_isom_segment_get_fragment_size(isom_file, moof_index, NULL);
    gf_isom_get_omadrm_info(isom_file, trackNumber, 1, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outContentID, &outRightsIssuerURL, &outTextualHeaders, &outTextualHeadersLen, &outPlaintextLength, &outEncryptionType, &outSelectiveEncryption, &outIVLength, &outKeyIndicationLength);

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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
