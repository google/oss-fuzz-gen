// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_chapter_count at isom_read.c:1526:5 in isomedia.h
// gf_isom_get_next_moof_number at movie_fragments.c:3482:5 in isomedia.h
// gf_isom_get_last_created_track_id at isom_write.c:596:15 in isomedia.h
// gf_isom_get_media_timescale at isom_read.c:1459:5 in isomedia.h
// gf_isom_get_chunk_count at isom_read.c:6307:5 in isomedia.h
// gf_isom_segment_get_fragment_count at isom_read.c:864:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isoFile = NULL;

    // Write dummy data to a file
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        // Open the file with the GPAC library function to get a GF_ISOFile pointer
        isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    }

    return isoFile;
}

static void cleanup_iso_file(GF_ISOFile *isoFile) {
    if (isoFile) {
        gf_isom_close(isoFile);
    }
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isoFile = initialize_iso_file(Data, Size);
    if (!isoFile) return 0;

    // Fuzz gf_isom_get_chapter_count
    u32 trackNumber = Data[0] % 256; // Use the first byte as trackNumber
    u32 chapterCount = gf_isom_get_chapter_count(isoFile, trackNumber);

    // Fuzz gf_isom_get_next_moof_number
    u32 nextMoofNumber = gf_isom_get_next_moof_number(isoFile);

    // Fuzz gf_isom_get_last_created_track_id
    GF_ISOTrackID lastTrackID = gf_isom_get_last_created_track_id(isoFile);

    // Fuzz gf_isom_get_media_timescale
    u32 mediaTimescale = gf_isom_get_media_timescale(isoFile, trackNumber);

    // Fuzz gf_isom_get_chunk_count
    u32 chunkCount = gf_isom_get_chunk_count(isoFile, trackNumber);

    // Fuzz gf_isom_segment_get_fragment_count
    u32 fragmentCount = gf_isom_segment_get_fragment_count(isoFile);

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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    