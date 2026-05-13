// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_track_creation_time at isom_write.c:230:8 in isomedia.h
// gf_isom_get_sample_for_movie_time at isom_read.c:2365:8 in isomedia.h
// gf_isom_get_sample_for_media_time at isom_read.c:2192:8 in isomedia.h
// gf_isom_add_sample_reference at isom_write.c:1269:8 in isomedia.h
// gf_isom_update_sample_reference at isom_write.c:1477:8 in isomedia.h
// gf_isom_get_media_time at isom_read.c:1342:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE "./dummy_file"

static GF_ISOFile *initialize_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static GF_ISOSample *initialize_sample() {
    GF_ISOSample *sample = (GF_ISOSample *)malloc(sizeof(GF_ISOSample));
    if (!sample) return NULL;
    memset(sample, 0, sizeof(GF_ISOSample));
    return sample;
}

int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + sizeof(u64) * 2) return 0;

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u64 create_time = *(u64 *)(Data + sizeof(u32));
    u64 modif_time = *(u64 *)(Data + sizeof(u32) + sizeof(u64));

    // Fuzz gf_isom_set_track_creation_time
    gf_isom_set_track_creation_time(isom_file, trackNumber, create_time, modif_time);

    // Fuzz gf_isom_get_sample_for_movie_time
    u64 movieTime = *(u64 *)(Data + sizeof(u32) + 2 * sizeof(u64));
    u32 *sampleDescriptionIndex = NULL;
    GF_ISOSearchMode searchMode = (GF_ISOSearchMode)(*(u32 *)(Data + sizeof(u32) + 3 * sizeof(u64)));
    GF_ISOSample *sample = initialize_sample();
    u32 sample_number = 0;
    u64 data_offset = 0;
    gf_isom_get_sample_for_movie_time(isom_file, trackNumber, movieTime, sampleDescriptionIndex, searchMode, &sample, &sample_number, &data_offset);

    // Fuzz gf_isom_get_sample_for_media_time
    u64 desiredTime = *(u64 *)(Data + sizeof(u32) + 4 * sizeof(u64));
    gf_isom_get_sample_for_media_time(isom_file, trackNumber, desiredTime, sampleDescriptionIndex, searchMode, &sample, &sample_number, &data_offset);

    // Fuzz gf_isom_add_sample_reference
    u32 sampleDescriptionIndex2 = *(u32 *)(Data + sizeof(u32) + 5 * sizeof(u64));
    u64 dataOffset = *(u64 *)(Data + sizeof(u32) + 6 * sizeof(u64));
    gf_isom_add_sample_reference(isom_file, trackNumber, sampleDescriptionIndex2, sample, dataOffset);

    // Fuzz gf_isom_update_sample_reference
    u32 sampleNumber = *(u32 *)(Data + sizeof(u32) + 7 * sizeof(u64));
    gf_isom_update_sample_reference(isom_file, trackNumber, sampleNumber, sample, dataOffset);

    // Fuzz gf_isom_get_media_time
    u64 mediaTime = 0;
    gf_isom_get_media_time(isom_file, trackNumber, (u32)movieTime, &mediaTime);

    gf_isom_close(isom_file);
    free(sample);

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

        LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    