#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_iso_file_from_data(const uint8_t *Data, size_t Size) {
    // Assume a valid ISO file is created from the data
    // In a real scenario, this should be replaced with actual file parsing
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isoFile;
}

static void cleanup_iso_file(GF_ISOFile *isoFile) {
    if (isoFile) {
        gf_isom_close(isoFile);
    }
}

int LLVMFuzzerTestOneInput_156(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *isoFile = create_iso_file_from_data(Data, Size);
    if (!isoFile) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 sampleNumber = *((u32 *)(Data + 2 * sizeof(u32)));

    // Invoke gf_isom_get_max_sample_delta
    u32 maxSampleDelta = gf_isom_get_max_sample_delta(isoFile, trackNumber);

    // Invoke gf_isom_get_payt_count
    u32 paytCount = gf_isom_get_payt_count(isoFile, trackNumber);

    // Invoke gf_isom_get_sync_point_count
    u32 syncPointCount = gf_isom_get_sync_point_count(isoFile, trackNumber);

    // Invoke gf_isom_iamf_config_get
    GF_IAConfig *iamfConfig = gf_isom_iamf_config_get(isoFile, trackNumber, sampleDescriptionIndex);
    if (iamfConfig) {
        // Assume there's a function to delete the config
        // delete_iamf_config(iamfConfig); // Placeholder for actual cleanup
    }

    // Invoke gf_isom_get_sample_duration
    u32 sampleDuration = gf_isom_get_sample_duration(isoFile, trackNumber, sampleNumber);

    // Invoke gf_isom_get_constant_sample_size
    u32 constantSampleSize = gf_isom_get_constant_sample_size(isoFile, trackNumber);

    // Cleanup
    cleanup_iso_file(isoFile);

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

    LLVMFuzzerTestOneInput_156(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
