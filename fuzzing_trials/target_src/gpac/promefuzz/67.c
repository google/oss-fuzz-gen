// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_add_sample_shadow at isom_write.c:1142:8 in isomedia.h
// gf_isom_hint_max_chunk_size at isom_write.c:5898:8 in isomedia.h
// gf_isom_add_sample at isom_write.c:1061:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8354:8 in isomedia.h
// gf_isom_begin_hint_sample at hint_track.c:324:8 in isomedia.h
// gf_isom_update_sample at isom_write.c:1438:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate memory for the GF_ISOFile structure
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static GF_ISOSample* create_dummy_sample() {
    // Allocate memory for the GF_ISOSample structure
    GF_ISOSample *sample = (GF_ISOSample *)malloc(sizeof(GF_ISOSample));
    if (!sample) return NULL;
    memset(sample, 0, sizeof(GF_ISOSample));
    return sample;
}

int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 6 + sizeof(Bool)) return 0;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    GF_ISOSample *sample = create_dummy_sample();
    if (!sample) {
        gf_isom_close(iso_file);
        return 0;
    }

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 maxChunkSize = *(u32 *)(Data + 2 * sizeof(u32));
    u32 sampleNumber = *(u32 *)(Data + 3 * sizeof(u32));
    u32 HintDescriptionIndex = *(u32 *)(Data + 4 * sizeof(u32));
    u32 TransmissionTime = *(u32 *)(Data + 5 * sizeof(u32));
    Bool data_only = *(Bool *)(Data + 6 * sizeof(u32));

    // Fuzz gf_isom_add_sample_shadow
    gf_isom_add_sample_shadow(iso_file, trackNumber, sample);

    // Fuzz gf_isom_hint_max_chunk_size
    gf_isom_hint_max_chunk_size(iso_file, trackNumber, maxChunkSize);

    // Fuzz gf_isom_add_sample
    gf_isom_add_sample(iso_file, trackNumber, sampleDescriptionIndex, sample);

    // Fuzz gf_isom_update_edit_list_duration
    gf_isom_update_edit_list_duration(iso_file, trackNumber);

    // Fuzz gf_isom_begin_hint_sample
    gf_isom_begin_hint_sample(iso_file, trackNumber, HintDescriptionIndex, TransmissionTime);

    // Fuzz gf_isom_update_sample
    gf_isom_update_sample(iso_file, trackNumber, sampleNumber, sample, data_only);

    // Cleanup
    free(sample);
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

        LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    