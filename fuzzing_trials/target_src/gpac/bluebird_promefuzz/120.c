#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate a block of memory large enough to simulate a GF_ISOFile
    return (GF_ISOFile*)calloc(1, 1024); // Assuming 1024 bytes is sufficient for fuzzing purposes
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        free(isom_file);
    }
}

int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 duration = *(u32*)(Data + sizeof(u32));
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32) * 2);

    // Fuzz gf_isom_set_last_sample_duration
    gf_isom_set_last_sample_duration(isom_file, trackNumber, duration);

    // Fuzz gf_isom_get_bitrate
    u32 average_bitrate = 0, max_bitrate = 0, decode_buffer_size = 0;
    gf_isom_get_bitrate(isom_file, trackNumber, sampleDescriptionIndex, &average_bitrate, &max_bitrate, &decode_buffer_size);

    // Fuzz gf_isom_set_mpegh_compatible_profiles
    const u32 profiles[] = {1, 2, 3};
    gf_isom_set_mpegh_compatible_profiles(isom_file, trackNumber, sampleDescriptionIndex, profiles, 3);

    // Fuzz gf_isom_lhvc_force_inband_config
    gf_isom_lhvc_force_inband_config(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_original_format_type
    u32 outOriginalFormat = 0;
    gf_isom_get_original_format_type(isom_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat);

    // Fuzz gf_isom_mvc_config_del
    gf_isom_mvc_config_del(isom_file, trackNumber, sampleDescriptionIndex);

    cleanup_iso_file(isom_file);
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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
