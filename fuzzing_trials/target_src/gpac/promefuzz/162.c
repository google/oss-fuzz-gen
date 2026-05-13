// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_track_creation_time at isom_write.c:230:8 in isomedia.h
// gf_isom_set_fragment_reference_time at movie_fragments.c:2552:8 in isomedia.h
// gf_isom_set_creation_time at isom_write.c:221:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
// gf_isom_set_movie_duration at movie_fragments.c:61:8 in isomedia.h
// gf_isom_get_media_duration at isom_read.c:1426:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    // Assuming there is a function to create or initialize it.
    // This placeholder function should be replaced with the actual function from the library.
    return NULL;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    // Assuming there is a function to close or cleanup the file.
    // This placeholder function should be replaced with the actual function from the library.
}

int LLVMFuzzerTestOneInput_162(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) + sizeof(u64) * 6 + sizeof(Bool) * 2) {
        return 0;
    }

    GF_ISOFile *iso_file = initialize_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u64 create_time = *((u64 *)(Data + sizeof(u32)));
    u64 modif_time = *((u64 *)(Data + sizeof(u32) + sizeof(u64)));
    u64 bytes_removed = *((u64 *)(Data + sizeof(u32) + sizeof(u64) * 2));
    u64 duration = *((u64 *)(Data + sizeof(u32) + sizeof(u64) * 3));
    Bool remove_mehd = *((Bool *)(Data + sizeof(u32) + sizeof(u64) * 4));
    GF_ISOTrackID reference_track_ID = *((GF_ISOTrackID *)(Data + sizeof(u32) + sizeof(u64) * 4 + sizeof(Bool)));
    u64 ntp = *((u64 *)(Data + sizeof(u32) + sizeof(u64) * 5 + sizeof(Bool)));
    u64 timestamp = *((u64 *)(Data + sizeof(u32) + sizeof(u64) * 6 + sizeof(Bool)));
    Bool at_mux = *((Bool *)(Data + sizeof(u32) + sizeof(u64) * 7 + sizeof(Bool)));

    gf_isom_set_track_creation_time(iso_file, trackNumber, create_time, modif_time);
    gf_isom_set_fragment_reference_time(iso_file, reference_track_ID, ntp, timestamp, at_mux);
    gf_isom_set_creation_time(iso_file, create_time, modif_time);
    gf_isom_set_removed_bytes(iso_file, bytes_removed);
    gf_isom_set_movie_duration(iso_file, duration, remove_mehd);
    gf_isom_get_media_duration(iso_file, trackNumber);

    cleanup_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_162(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    