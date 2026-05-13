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

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(Bool)) return 0;

    // Prepare dummy file
    write_dummy_file(Data, Size);

    // Initialize variables for target functions
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleNumber = *(u32 *)(Data + sizeof(u32));
    Bool is_rap = *(Bool *)(Data + sizeof(u32) * 2);
    u32 num_leading_samples = *(u32 *)(Data + sizeof(u32) * 2 + sizeof(Bool));

    // 1. Test gf_isom_set_sample_rap_group
    gf_isom_set_sample_rap_group(isom_file, trackNumber, sampleNumber, is_rap, num_leading_samples);

    // 2. Test gf_isom_vvc_set_inband_config
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32) * 3 + sizeof(Bool));
    Bool keep_xps = *(Bool *)(Data + sizeof(u32) * 4 + sizeof(Bool));
    gf_isom_vvc_set_inband_config(isom_file, trackNumber, sampleDescriptionIndex, keep_xps);

    // 3. Test gf_isom_fragment_set_sample_rap_group
    gf_isom_fragment_set_sample_rap_group(isom_file, trackNumber, sampleNumber, is_rap, num_leading_samples);

    // 4. Test gf_isom_fragment_set_sample_av1_switch_frame_group
    gf_isom_fragment_set_sample_av1_switch_frame_group(isom_file, trackNumber, sampleNumber, is_rap);

    // 5. Test gf_isom_finalize_for_fragment
    u32 media_segment_type = *(u32 *)(Data + sizeof(u32) * 5 + sizeof(Bool));
    Bool mvex_after_tracks = *(Bool *)(Data + sizeof(u32) * 6 + sizeof(Bool));
    gf_isom_finalize_for_fragment(isom_file, media_segment_type, mvex_after_tracks);

    // 6. Test gf_isom_get_sample_rap_roll_info
    Bool is_rap_result;
    GF_ISOSampleRollType roll_type;
    s32 roll_distance;
    gf_isom_get_sample_rap_roll_info(isom_file, trackNumber, sampleNumber, &is_rap_result, &roll_type, &roll_distance);

    // Cleanup
    gf_isom_close(isom_file);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
