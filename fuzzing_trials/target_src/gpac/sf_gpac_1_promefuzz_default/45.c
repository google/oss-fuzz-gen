// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_segment_get_fragment_count at isom_read.c:864:5 in isomedia.h
// gf_isom_get_constant_sample_size at isom_read.c:1780:5 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_track_by_id at isom_read.c:807:5 in isomedia.h
// gf_isom_get_track_count at isom_read.c:783:5 in isomedia.h
// gf_isom_get_chunk_count at isom_read.c:6307:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_ISOFILE_SIZE 1024

static GF_ISOFile* create_dummy_isofile() {
    // Allocate memory for a dummy GF_ISOFile object
    GF_ISOFile* isofile = (GF_ISOFile*)malloc(DUMMY_ISOFILE_SIZE);
    if (!isofile) return NULL;
    memset(isofile, 0, DUMMY_ISOFILE_SIZE);
    return isofile;
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < DUMMY_ISOFILE_SIZE) return 0;
    
    GF_ISOFile* isofile = create_dummy_isofile();
    if (!isofile) return 0;

    // Populate the dummy ISO file with some data from the input
    memcpy(isofile, Data, DUMMY_ISOFILE_SIZE < Size ? DUMMY_ISOFILE_SIZE : Size);

    // Test gf_isom_segment_get_fragment_count
    u32 fragment_count = gf_isom_segment_get_fragment_count(isofile);

    // Test gf_isom_get_constant_sample_size
    u32 track_number = (Size > 4) ? *(u32*)(Data + 4) : 0;
    u32 sample_size = gf_isom_get_constant_sample_size(isofile, track_number);

    // Test gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isofile);

    // Test gf_isom_get_track_by_id
    GF_ISOTrackID track_id = (Size > 8) ? *(GF_ISOTrackID*)(Data + 8) : 0;
    u32 track_num_by_id = gf_isom_get_track_by_id(isofile, track_id);

    // Test gf_isom_get_track_count
    u32 track_count = gf_isom_get_track_count(isofile);

    // Test gf_isom_get_chunk_count
    u32 chunk_count = gf_isom_get_chunk_count(isofile, track_number);

    // Cleanup
    free(isofile);

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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    