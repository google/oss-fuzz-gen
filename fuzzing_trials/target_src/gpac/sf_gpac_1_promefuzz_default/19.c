// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_payt_count at hint_track.c:968:5 in isomedia.h
// gf_isom_get_highest_track_in_scalable_segment at isom_read.c:3640:15 in isomedia.h
// gf_isom_set_default_sync_track at isom_read.c:4209:6 in isomedia.h
// gf_isom_get_track_id at isom_read.c:796:15 in isomedia.h
// gf_isom_has_time_offset at isom_read.c:1868:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

// Since GF_ISOFile is a forward declaration, we cannot instantiate it directly.
// We will assume a dummy size for fuzzing purposes.
#define DUMMY_ISOFILE_SIZE 1024

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < DUMMY_ISOFILE_SIZE + sizeof(u32)) {
        return 0;
    }

    // Allocate memory for a dummy GF_ISOFile
    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(DUMMY_ISOFILE_SIZE);
    if (!isom_file) return 0;

    // Copy data into the allocated dummy GF_ISOFile structure
    memcpy(isom_file, Data, DUMMY_ISOFILE_SIZE);
    u32 trackNumber = *(u32 *)(Data + DUMMY_ISOFILE_SIZE);

    // Invoke gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Invoke gf_isom_get_payt_count
    u32 payt_count = gf_isom_get_payt_count(isom_file, trackNumber);

    // Invoke gf_isom_get_highest_track_in_scalable_segment
    GF_ISOTrackID highest_track_id = gf_isom_get_highest_track_in_scalable_segment(isom_file, trackNumber);

    // Invoke gf_isom_set_default_sync_track
    gf_isom_set_default_sync_track(isom_file, trackNumber);

    // Invoke gf_isom_get_track_id
    GF_ISOTrackID track_id = gf_isom_get_track_id(isom_file, trackNumber);

    // Invoke gf_isom_has_time_offset
    u32 time_offset = gf_isom_has_time_offset(isom_file, trackNumber);

    // Free allocated memory
    free(isom_file);

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    