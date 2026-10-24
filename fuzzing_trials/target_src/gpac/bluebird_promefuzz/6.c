#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2 + sizeof(Bool)) {
        return 0;
    }

    prepare_dummy_file(Data, Size);

    const char *fileName = "./dummy_file";
    u64 start_range = *(u64 *)Data;
    u64 end_range = *(u64 *)(Data + sizeof(u64));
    Bool enable_frag_templates = *(Bool *)(Data + sizeof(u64) * 2);

    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;

    gf_isom_open_progressive_ex(fileName, start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);

    if (isom_file) {
        GF_ISOTrackID reference_track_ID = 1;
        u64 ntp = 0;
        u64 timestamp = 0;
        Bool at_mux = GF_FALSE;

        gf_isom_set_fragment_reference_time(isom_file, reference_track_ID, ntp, timestamp, at_mux);

        u32 trackNumber = 1;
        gf_isom_refresh_size_info(isom_file, trackNumber);

        s32 subsegs_per_sidx = 0;
        u64 ref_track_decode_time = 0;
        s32 timestamp_shift = 0;
        u64 ref_track_next_cts = 0;
        Bool daisy_chain_sidx = GF_FALSE;
        Bool use_ssix = GF_FALSE;
        Bool last_segment = GF_FALSE;
        Bool close_segment_handle = GF_FALSE;
        u32 segment_marker_4cc = 0;
        u64 index_start_range = 0;
        u64 index_end_range = 0;
        u64 out_seg_size = 0;

        gf_isom_close_segment(isom_file, subsegs_per_sidx, reference_track_ID, ref_track_decode_time, timestamp_shift, ref_track_next_cts, daisy_chain_sidx, use_ssix, last_segment, close_segment_handle, segment_marker_4cc, &index_start_range, &index_end_range, &out_seg_size);

        u32 movieTime = 0;
        u64 mediaTime = 0;
        gf_isom_get_media_time(isom_file, trackNumber, movieTime, &mediaTime);

        u32 outOriginalFormat = 0;
        u32 outSchemeType = 0;
        u32 outSchemeVersion = 0;
        const char *outContentID = NULL;
        const char *outRightsIssuerURL = NULL;
        const char *outTextualHeaders = NULL;
        u32 outTextualHeadersLen = 0;
        u64 outPlaintextLength = 0;
        u32 outEncryptionType = 0;
        Bool outSelectiveEncryption = GF_FALSE;
        u32 outIVLength = 0;
        u32 outKeyIndicationLength = 0;

        gf_isom_get_omadrm_info(isom_file, trackNumber, 1, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outContentID, &outRightsIssuerURL, &outTextualHeaders, &outTextualHeadersLen, &outPlaintextLength, &outEncryptionType, &outSelectiveEncryption, &outIVLength, &outKeyIndicationLength);

        // Clean up operations
        // Assuming there's a function to close/free the isom_file
        // gf_isom_close(isom_file);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
