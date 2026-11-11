#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;

    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isoFile;
}

int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *isoFile = initialize_iso_file(Data, Size);
    if (!isoFile) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32));
    u32 sampleNumber = *(u32*)(Data + 2 * sizeof(u32));

    // Call gf_isom_get_max_sample_size
    u32 maxSampleSize = gf_isom_get_max_sample_size(isoFile, trackNumber);

    // Call gf_isom_get_sample_description_count
    u32 sampleDescriptionCount = gf_isom_get_sample_description_count(isoFile, trackNumber);

    // Call gf_isom_get_highest_track_in_scalable_segment
    GF_ISOTrackID highestTrackID = gf_isom_get_highest_track_in_scalable_segment(isoFile, trackNumber);

    // Call gf_isom_get_track_count
    u32 trackCount = gf_isom_get_track_count(isoFile);

    // Call gf_isom_get_content_light_level_info
    const GF_ContentLightLevelInfo *clliInfo = gf_isom_get_content_light_level_info(isoFile, trackNumber, sampleDescriptionIndex);

    // Call gf_isom_sample_has_subsamples
    u32 subsampleCount = gf_isom_sample_has_subsamples(isoFile, trackNumber, sampleNumber, 0);

    // Clean up
    gf_isom_close(isoFile);
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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
