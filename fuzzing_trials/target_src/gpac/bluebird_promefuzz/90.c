#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void initialize_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) + sizeof(u64)) return 0;

    // Initialize a dummy file with the input data
    initialize_dummy_file(Data, Size);

    // Create a dummy GF_ISOFile object
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Extract trackNumber and dts/sampleNumber from the input data
    u32 trackNumber = *((u32 *)Data);
    u64 dts_sampleNumber = *((u64 *)(Data + sizeof(u32)));

    // Call each target function with the dummy data
    u64 duration_orig = gf_isom_get_track_duration_orig(isom_file, trackNumber);
    u32 sample_from_dts = gf_isom_get_sample_from_dts(isom_file, trackNumber, dts_sampleNumber);
    u64 sample_dts = gf_isom_get_sample_dts(isom_file, trackNumber, (u32)dts_sampleNumber);
    u64 smooth_next_tfdt = gf_isom_get_smooth_next_tfdt(isom_file, trackNumber);
    u64 media_duration = gf_isom_get_media_duration(isom_file, trackNumber);
    u64 track_magic = gf_isom_get_track_magic(isom_file, trackNumber);

    // Output the results to avoid optimization removal
    printf("Duration Orig: %llu\n", duration_orig);
    printf("Sample From DTS: %u\n", sample_from_dts);
    printf("Sample DTS: %llu\n", sample_dts);
    printf("Smooth Next TFDT: %llu\n", smooth_next_tfdt);
    printf("Media Duration: %llu\n", media_duration);
    printf("Track Magic: %llu\n", track_magic);

    // Clean up
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
