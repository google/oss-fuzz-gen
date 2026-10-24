#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we can't allocate it directly.
    // Instead, we assume the library provides a function to create or initialize it.
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_160(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Ensure enough data for multiple u32 values

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32*)Data);
    u32 duration = *((u32*)(Data + 4));
    u32 hintDescriptionIndex = *((u32*)(Data + 8));
    u32 timeOffset = *((u32*)(Data + 12));

    // Fuzz gf_isom_set_last_sample_duration
    gf_isom_set_last_sample_duration(iso_file, trackNumber, duration);

    // Fuzz gf_isom_rtp_set_time_offset
    gf_isom_rtp_set_time_offset(iso_file, trackNumber, hintDescriptionIndex, timeOffset);

    // Prepare a dummy VVCConfig for gf_isom_vvc_config_update
    GF_VVCConfig *vvc_config = (GF_VVCConfig*)malloc(sizeof(GF_VVCConfig));
    if (vvc_config) {
        memset(vvc_config, 0, sizeof(GF_VVCConfig));
        if (Size >= 20) { // Ensure there's enough data to read sampleDescriptionIndex
            u32 sampleDescriptionIndex = *((u32*)(Data + 16));
            gf_isom_vvc_config_update(iso_file, trackNumber, sampleDescriptionIndex, vvc_config);
        }
        free(vvc_config);
    }

    // Fuzz gf_isom_lhvc_force_inband_config
    gf_isom_lhvc_force_inband_config(iso_file, trackNumber, hintDescriptionIndex);

    // Fuzz gf_isom_get_original_format_type
    u32 outOriginalFormat;
    gf_isom_get_original_format_type(iso_file, trackNumber, hintDescriptionIndex, &outOriginalFormat);

    // Fuzz gf_isom_sdp_clean_track
    gf_isom_sdp_clean_track(iso_file, trackNumber);

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

    LLVMFuzzerTestOneInput_160(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
