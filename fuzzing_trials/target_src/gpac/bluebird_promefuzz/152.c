#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_152(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Initialize a dummy GF_ISOFile object
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);

    if (!isom_file) return 0;

    // Extract a track number from the input data
    u32 trackNumber = *(u32 *)Data;

    // Call gf_isom_get_track_id
    GF_ISOTrackID trackID = gf_isom_get_track_id(isom_file, trackNumber);

    // Call gf_isom_get_track_flags
    u32 trackFlags = gf_isom_get_track_flags(isom_file, trackNumber);

    // Call gf_isom_set_default_sync_track
    gf_isom_set_default_sync_track(isom_file, trackNumber);

    // Call gf_isom_get_brands
    const u32 *brands = gf_isom_get_brands(isom_file);

    // Call gf_isom_avs3v_config_get
    GF_AVS3VConfig *avs3Config = gf_isom_avs3v_config_get(isom_file, trackNumber, 0);
    if (avs3Config) {
        // Free the AVS3 configuration if it was successfully retrieved
        free(avs3Config);
    }

    // Call gf_isom_get_constant_sample_duration
    u32 sampleDuration = gf_isom_get_constant_sample_duration(isom_file, trackNumber);

    // Close the ISO file
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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
