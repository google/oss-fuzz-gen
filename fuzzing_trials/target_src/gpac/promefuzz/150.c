// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_max_sample_cts_offset at isom_read.c:2070:5 in isomedia.h
// gf_isom_get_track_by_id at isom_read.c:807:5 in isomedia.h
// gf_isom_get_sample_description_count at isom_read.c:1373:5 in isomedia.h
// gf_isom_get_chapter_count at isom_read.c:1526:5 in isomedia.h
// gf_isom_get_sample_size at isom_read.c:2007:5 in isomedia.h
// gf_isom_get_constant_sample_size at isom_read.c:1780:5 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* open_dummy_iso_file() {
    // Create a dummy ISO file for testing purposes
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void close_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = open_dummy_iso_file();
    if (!isom_file) return 0;

    // Use a portion of the data to determine trackNumber and trackID
    u32 trackNumber = (Size > 4) ? *((u32*)Data) : 1;
    GF_ISOTrackID trackID = (Size > 8) ? *((u32*)(Data + 4)) : 1;
    u32 sampleNumber = (Size > 12) ? *((u32*)(Data + 8)) : 1;

    // Invoke the target functions with various inputs
    u32 max_cts_offset = gf_isom_get_max_sample_cts_offset(isom_file, trackNumber);
    u32 track_by_id = gf_isom_get_track_by_id(isom_file, trackID);
    u32 sample_desc_count = gf_isom_get_sample_description_count(isom_file, trackNumber);
    u32 chapter_count = gf_isom_get_chapter_count(isom_file, trackNumber);
    u32 sample_size = gf_isom_get_sample_size(isom_file, trackNumber, sampleNumber);
    u32 constant_sample_size = gf_isom_get_constant_sample_size(isom_file, trackNumber);

    // Handle the return values, if necessary
    (void)max_cts_offset;
    (void)track_by_id;
    (void)sample_desc_count;
    (void)chapter_count;
    (void)sample_size;
    (void)constant_sample_size;

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

        LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    