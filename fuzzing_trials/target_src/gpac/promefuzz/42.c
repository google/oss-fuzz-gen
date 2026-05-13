// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_has_segment at isom_read.c:843:6 in isomedia.h
// gf_isom_is_track_fragmented at movie_fragments.c:3512:6 in isomedia.h
// gf_isom_is_track_encrypted at isom_read.c:1624:6 in isomedia.h
// gf_isom_is_self_contained at isom_read.c:2158:6 in isomedia.h
// gf_isom_is_ismacryp_media at drm_sample.c:218:6 in isomedia.h
// gf_isom_get_tile_info at isom_read.c:5878:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static GF_ISOFile* open_dummy_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void close_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy ISO file
    write_dummy_file(Data, Size);

    // Open the dummy ISO file
    GF_ISOFile *isom_file = open_dummy_iso_file();
    if (!isom_file) return 0;

    // Set up dummy values for brand and version
    u32 brand = 0;
    u32 version = 0;

    // Invoke gf_isom_has_segment
    gf_isom_has_segment(isom_file, &brand, &version);

    // Set up dummy values for track ID
    GF_ISOTrackID trackID = 1;

    // Invoke gf_isom_is_track_fragmented
    gf_isom_is_track_fragmented(isom_file, trackID);

    // Invoke gf_isom_is_track_encrypted
    gf_isom_is_track_encrypted(isom_file, trackID);

    // Set up dummy values for sample description index
    u32 sampleDescriptionIndex = 1;

    // Invoke gf_isom_is_self_contained
    gf_isom_is_self_contained(isom_file, trackID, sampleDescriptionIndex);

    // Invoke gf_isom_is_ismacryp_media
    gf_isom_is_ismacryp_media(isom_file, trackID, sampleDescriptionIndex);

    // Set up dummy values for gf_isom_get_tile_info parameters
    u32 default_sample_group_index = 0;
    u32 id = 0;
    u32 independent = 0;
    Bool full_frame = GF_FALSE;
    u32 x = 0, y = 0, w = 0, h = 0;

    // Invoke gf_isom_get_tile_info
    gf_isom_get_tile_info(isom_file, trackID, sampleDescriptionIndex, &default_sample_group_index, &id, &independent, &full_frame, &x, &y, &w, &h);

    // Cleanup
    close_dummy_iso_file(isom_file);

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    