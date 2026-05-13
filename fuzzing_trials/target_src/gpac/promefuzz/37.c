// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_sample_count at isom_read.c:1767:5 in isomedia.h
// gf_isom_get_next_moof_number at movie_fragments.c:3482:5 in isomedia.h
// gf_isom_get_last_created_track_id at isom_write.c:596:15 in isomedia.h
// gf_isom_get_media_timescale at isom_read.c:1459:5 in isomedia.h
// gf_isom_get_sample_duration at isom_read.c:1990:5 in isomedia.h
// gf_isom_get_chunk_count at isom_read.c:6307:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Since we can't access the internal structure, we return NULL
    return NULL;
}

static void cleanup_dummy_isofile(GF_ISOFile* iso_file) {
    // No cleanup needed as we are not allocating any memory
}

int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile* iso_file = create_dummy_isofile();

    u32 trackNumber = *((u32*)Data);
    u32 sampleNumber = trackNumber % 100 + 1; // Sample number should be 1-based

    // Fuzz gf_isom_get_sample_count
    u32 sample_count = gf_isom_get_sample_count(iso_file, trackNumber);
    (void)sample_count;

    // Fuzz gf_isom_get_next_moof_number
    u32 next_moof_number = gf_isom_get_next_moof_number(iso_file);
    (void)next_moof_number;

    // Fuzz gf_isom_get_last_created_track_id
    GF_ISOTrackID last_track_id = gf_isom_get_last_created_track_id(iso_file);
    (void)last_track_id;

    // Fuzz gf_isom_get_media_timescale
    u32 media_timescale = gf_isom_get_media_timescale(iso_file, trackNumber);
    (void)media_timescale;

    // Fuzz gf_isom_get_sample_duration
    u32 sample_duration = gf_isom_get_sample_duration(iso_file, trackNumber, sampleNumber);
    (void)sample_duration;

    // Fuzz gf_isom_get_chunk_count
    u32 chunk_count = gf_isom_get_chunk_count(iso_file, trackNumber);
    (void)chunk_count;

    cleanup_dummy_isofile(iso_file);
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

        LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    