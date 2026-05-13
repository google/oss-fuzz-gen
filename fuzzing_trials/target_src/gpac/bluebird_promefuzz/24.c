#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_iso_file();

    if (!isom_file) return 0;

    // Prepare variables for gf_isom_get_audio_info
    u32 SampleRate = 0, Channels = 0, BitsPerSample = 0;
    u32 trackNumber = Size > 0 ? Data[0] : 1;
    u32 sampleDescriptionIndex = Size > 1 ? Data[1] : 1;
    gf_isom_get_audio_info(isom_file, trackNumber, sampleDescriptionIndex, &SampleRate, &Channels, &BitsPerSample);

    // Prepare variables for gf_isom_get_brand_info
    u32 brand = 0, minorVersion = 0, AlternateBrandsCount = 0;
    gf_isom_get_brand_info(isom_file, &brand, &minorVersion, &AlternateBrandsCount);

    // Prepare variables for gf_isom_set_nalu_extract_mode
    GF_ISONaluExtractMode nalu_extract_mode = (GF_ISONaluExtractMode)(Size > 2 ? Data[2] : 0);
    gf_isom_set_nalu_extract_mode(isom_file, trackNumber, nalu_extract_mode);

    // Invoke gf_isom_get_nalu_extract_mode
    gf_isom_get_nalu_extract_mode(isom_file, trackNumber);

    // Prepare variables for gf_isom_set_track_reference
    u32 referenceType = Size > 3 ? Data[3] : 0;
    GF_ISOTrackID ReferencedTrackID = Size > 4 ? Data[4] : 0;
    gf_isom_set_track_reference(isom_file, trackNumber, referenceType, ReferencedTrackID);

    // Prepare variables for gf_isom_get_tmcd_config
    u32 tmcd_flags = 0, tmcd_fps_num = 0, tmcd_fps_den = 0, tmcd_fpt = 0;
    gf_isom_get_tmcd_config(isom_file, trackNumber, sampleDescriptionIndex, &tmcd_flags, &tmcd_fps_num, &tmcd_fps_den, &tmcd_fpt);

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
