// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_hint_max_chunk_duration at isom_write.c:5913:8 in isomedia.h
// gf_isom_hint_max_chunk_size at isom_write.c:5898:8 in isomedia.h
// gf_isom_fragment_set_sample_flags at movie_fragments.c:3395:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8354:8 in isomedia.h
// gf_isom_set_last_sample_duration_ex at isom_write.c:1431:8 in isomedia.h
// gf_isom_begin_hint_sample at hint_track.c:324:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy file for testing
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fclose(file);

    // Open the ISO file in write mode
    GF_ISOFile* iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile* iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 maxChunkDur = *(u32*)(Data + sizeof(u32));
    u32 maxChunkSize = *(u32*)(Data + 2 * sizeof(u32));

    gf_isom_hint_max_chunk_duration(iso_file, trackNumber, maxChunkDur);
    gf_isom_hint_max_chunk_size(iso_file, trackNumber, maxChunkSize);

    if (Size >= sizeof(u32) * 6) {
        u32 trackID = *(u32*)(Data + 3 * sizeof(u32));
        u32 is_leading = *(u32*)(Data + 4 * sizeof(u32));
        u32 dependsOn = *(u32*)(Data + 5 * sizeof(u32));
        u32 dependedOn = *(u32*)(Data + 6 * sizeof(u32));
        u32 redundant = *(u32*)(Data + 7 * sizeof(u32));

        gf_isom_fragment_set_sample_flags(iso_file, trackID, is_leading, dependsOn, dependedOn, redundant);
    }

    gf_isom_update_edit_list_duration(iso_file, trackNumber);

    if (Size >= sizeof(u32) * 8) {
        u32 dur_num = *(u32*)(Data + 8 * sizeof(u32));
        u32 dur_den = *(u32*)(Data + 9 * sizeof(u32));

        gf_isom_set_last_sample_duration_ex(iso_file, trackNumber, dur_num, dur_den);
    }

    if (Size >= sizeof(u32) * 10) {
        u32 HintDescriptionIndex = *(u32*)(Data + 10 * sizeof(u32));
        u32 TransmissionTime = *(u32*)(Data + 11 * sizeof(u32));

        gf_isom_begin_hint_sample(iso_file, trackNumber, HintDescriptionIndex, TransmissionTime);
    }

    cleanup_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    