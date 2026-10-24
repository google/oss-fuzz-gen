// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_hevc_lhvc_type at avc_ext.c:2728:17 in isomedia.h
// gf_isom_get_highest_track_in_scalable_segment at isom_read.c:3640:15 in isomedia.h
// gf_isom_new_track at isom_write.c:863:5 in isomedia.h
// gf_isom_set_default_sync_track at isom_read.c:4209:6 in isomedia.h
// gf_isom_get_last_created_track_id at isom_write.c:596:15 in isomedia.h
// gf_isom_get_track_flags at isom_read.c:1064:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define ISOM_FILE_SIZE 1024

static void initialize_iso_file(GF_ISOFile *isom_file) {
    memset(isom_file, 0, ISOM_FILE_SIZE);
    // You can add more initialization if needed
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    // Clean up any allocated resources in GF_ISOFile if necessary
    // Assuming fileName is a dynamically allocated string
    // This is a simplified assumption and may need adjustment
}

int LLVMFuzzerTestOneInput_261(const uint8_t *Data, size_t Size) {
    if (Size < ISOM_FILE_SIZE + 3 * sizeof(u32)) {
        return 0;
    }

    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(ISOM_FILE_SIZE);
    if (!isom_file) {
        return 0;
    }
    initialize_iso_file(isom_file);

    // Simulate input data
    memcpy(isom_file, Data, ISOM_FILE_SIZE);
    u32 trackNumber = *(u32 *)(Data + ISOM_FILE_SIZE);
    u32 sampleDescriptionIndex = *(u32 *)(Data + ISOM_FILE_SIZE + sizeof(u32));
    u32 MediaType = *(u32 *)(Data + ISOM_FILE_SIZE + 2 * sizeof(u32));
    u32 TimeScale = *(u32 *)(Data + ISOM_FILE_SIZE + 3 * sizeof(u32));

    // Call gf_isom_get_track_flags
    u32 flags = gf_isom_get_track_flags(isom_file, trackNumber);

    // Call gf_isom_get_hevc_lhvc_type
    GF_ISOMHEVCType hevc_type = gf_isom_get_hevc_lhvc_type(isom_file, trackNumber, sampleDescriptionIndex);

    // Call gf_isom_get_highest_track_in_scalable_segment
    GF_ISOTrackID highest_track_id = gf_isom_get_highest_track_in_scalable_segment(isom_file, trackNumber);

    // Call gf_isom_new_track
    u32 new_track_number = gf_isom_new_track(isom_file, 0, MediaType, TimeScale);

    // Call gf_isom_get_last_created_track_id
    GF_ISOTrackID last_created_track_id = gf_isom_get_last_created_track_id(isom_file);

    // Call gf_isom_set_default_sync_track
    gf_isom_set_default_sync_track(isom_file, trackNumber);

    cleanup_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_261(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    