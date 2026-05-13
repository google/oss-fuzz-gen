#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    u32 trackNumber = 1;
    u32 StreamDescriptionIndex = 1;
    GF_MasteringDisplayColourVolumeInfo mdcv;
    GF_ContentLightLevelInfo clli;

    // Ensure that the input data is large enough to populate the structures
    if (size < sizeof(GF_MasteringDisplayColourVolumeInfo) + sizeof(GF_ContentLightLevelInfo)) {
        gf_isom_close(movie);
        return 0;
    }

    // Populate mdcv and clli from the input data
    memcpy(&mdcv, data, sizeof(GF_MasteringDisplayColourVolumeInfo));
    memcpy(&clli, data + sizeof(GF_MasteringDisplayColourVolumeInfo), sizeof(GF_ContentLightLevelInfo));

    // Call the function under test
    gf_isom_set_high_dynamic_range_info(movie, trackNumber, StreamDescriptionIndex, &mdcv, &clli);

    // Clean up
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
