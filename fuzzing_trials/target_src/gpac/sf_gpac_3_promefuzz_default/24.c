// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_remove_track_references at isom_write.c:5155:8 in isomedia.h
// gf_isom_remove_track at isom_write.c:3061:8 in isomedia.h
// gf_isom_set_inplace_padding at isom_read.c:88:8 in isomedia.h
// gf_isom_set_interleave_time at isom_write.c:3550:8 in isomedia.h
// gf_isom_sdp_clean_track at hint_track.c:790:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile *create_dummy_iso_file() {
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return NULL;
    return iso_file;
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for a track number

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 padding = Size > 4 ? *((u32 *)(Data + 4)) : 0;
    u32 interleaveTime = Size > 8 ? *((u32 *)(Data + 8)) : 0;

    // Test gf_isom_remove_track_references
    gf_isom_remove_track_references(iso_file, trackNumber);

    // Test gf_isom_remove_track
    gf_isom_remove_track(iso_file, trackNumber);

    // Test gf_isom_set_inplace_padding
    gf_isom_set_inplace_padding(iso_file, padding);

    // Test gf_isom_set_interleave_time
    gf_isom_set_interleave_time(iso_file, interleaveTime);

    // Test gf_isom_sdp_clean_track
    gf_isom_sdp_clean_track(iso_file, trackNumber);

    // Cleanup and close the ISO file
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    