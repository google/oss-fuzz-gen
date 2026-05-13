// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_max_sample_size at isom_read.c:2021:5 in isomedia.h
// gf_isom_get_track_flags at isom_read.c:1064:5 in isomedia.h
// gf_isom_get_track_count at isom_read.c:783:5 in isomedia.h
// gf_isom_is_media_encrypted at drm_sample.c:193:5 in isomedia.h
// gf_isom_get_avg_sample_size at isom_read.c:2030:5 in isomedia.h
// gf_isom_sample_has_subsamples at isom_read.c:4909:5 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

static GF_ISOFile* load_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    