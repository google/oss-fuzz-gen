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

static GF_ISOFile* load_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data

    GF_ISOFile *iso_file = load_iso_file(Data, Size);
    if (!iso_file) return 0;

    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = Data[1];
    u32 sampleNumber = Data[2];
    u32 flags = Data[3];

    // Fuzz gf_isom_get_max_sample_size
    u32 max_sample_size = gf_isom_get_max_sample_size(iso_file, trackNumber);

    // Fuzz gf_isom_get_track_flags
    u32 track_flags = gf_isom_get_track_flags(iso_file, trackNumber);

    // Fuzz gf_isom_get_track_count
    u32 track_count = gf_isom_get_track_count(iso_file);

    // Fuzz gf_isom_is_media_encrypted
    u32 is_encrypted = gf_isom_is_media_encrypted(iso_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_avg_sample_size
    u32 avg_sample_size = gf_isom_get_avg_sample_size(iso_file, trackNumber);

    // Fuzz gf_isom_sample_has_subsamples
    u32 subsample_count = gf_isom_sample_has_subsamples(iso_file, trackNumber, sampleNumber, flags);

    // Clean up
    gf_isom_close(iso_file);

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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
