// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_is_track_fragmented at movie_fragments.c:3512:6 in isomedia.h
// gf_isom_sample_is_fragment_start at isom_read.c:6034:6 in isomedia.h
// gf_isom_has_sample_dependency at isom_read.c:1904:6 in isomedia.h
// gf_isom_enable_raw_pack at isom_read.c:1799:6 in isomedia.h
// gf_isom_is_track_encrypted at isom_read.c:1624:6 in isomedia.h
// gf_isom_get_sample_sync at isom_read.c:2080:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "isomedia.h"

static GF_ISOFile* load_iso_file(const uint8_t *Data, size_t Size) {
    // Simulate loading an ISO file from data
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

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Not enough data to extract track/sample numbers

    GF_ISOFile *isoFile = load_iso_file(Data, Size);
    if (!isoFile) return 0;

    // Extract track/sample numbers from Data
    u32 trackNumber = Data[0];
    u32 sampleNumber = Data[1];
    u32 packNumSamples = Data[2];
    GF_ISOTrackID trackID = Data[3];

    // Create a dummy fragment boundary info
    GF_ISOFragmentBoundaryInfo fragInfo;

    // Call the target functions with various inputs
    gf_isom_is_track_fragmented(isoFile, trackID);
    gf_isom_sample_is_fragment_start(isoFile, trackNumber, sampleNumber, &fragInfo);
    gf_isom_has_sample_dependency(isoFile, trackNumber);
    gf_isom_enable_raw_pack(isoFile, trackNumber, packNumSamples);
    gf_isom_is_track_encrypted(isoFile, trackNumber);
    gf_isom_get_sample_sync(isoFile, trackNumber, sampleNumber);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    