// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_track_kind_count at isom_read.c:1136:5 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_sample_count at isom_read.c:1767:5 in isomedia.h
// gf_isom_get_max_sample_size at isom_read.c:2021:5 in isomedia.h
// gf_isom_get_track_count at isom_read.c:783:5 in isomedia.h
// gf_isom_segment_get_track_fragment_count at isom_read.c:895:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Simulate opening an ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data % 10; // Simulate a track number from data
    u32 moof_index = *(u32 *)Data % 5;  // Simulate a moof index from data

    // Fuzz gf_isom_get_track_kind_count
    u32 kind_count = gf_isom_get_track_kind_count(isom_file, trackNumber);
    
    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_get_sample_count
    u32 sample_count = gf_isom_get_sample_count(isom_file, trackNumber);

    // Fuzz gf_isom_get_max_sample_size
    u32 max_sample_size = gf_isom_get_max_sample_size(isom_file, trackNumber);

    // Fuzz gf_isom_get_track_count
    u32 track_count = gf_isom_get_track_count(isom_file);

    // Fuzz gf_isom_segment_get_track_fragment_count
    u32 fragment_count = gf_isom_segment_get_track_fragment_count(isom_file, moof_index);

    // Cleanup
    cleanup_iso_file(isom_file);

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

        LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    