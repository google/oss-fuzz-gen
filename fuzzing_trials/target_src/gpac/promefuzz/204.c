// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_track_creation_time at isom_write.c:230:8 in isomedia.h
// gf_isom_get_fragmented_samples_info at isom_read.c:5436:8 in isomedia.h
// gf_isom_set_traf_base_media_decode_time at movie_fragments.c:3443:8 in isomedia.h
// gf_isom_patch_last_sample_duration at isom_write.c:1425:8 in isomedia.h
// gf_isom_set_media_creation_time at isom_write.c:242:8 in isomedia.h
// gf_isom_force_track_duration at isom_write.c:896:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static GF_ISOFile* create_dummy_iso_file() {
    // Assuming the existence of a function to create an ISO file in the GPAC library
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_204(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) + 4 * sizeof(u64)) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *) (Data));
    u64 create_time = *((u64 *) (Data + sizeof(u32)));
    u64 modif_time = *((u64 *) (Data + sizeof(u32) + sizeof(u64)));
    u64 decode_time = *((u64 *) (Data + sizeof(u32) + 2 * sizeof(u64)));
    u64 next_dts = *((u64 *) (Data + sizeof(u32) + 3 * sizeof(u64)));

    u32 nb_samples = 0;
    u64 duration = 0;
    GF_ISOTrackID trackID = trackNumber;

    // Initialize the dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_set_track_creation_time
    gf_isom_set_track_creation_time(isom_file, trackNumber, create_time, modif_time);

    // Test gf_isom_get_fragmented_samples_info
    gf_isom_get_fragmented_samples_info(isom_file, trackID, &nb_samples, &duration);

    // Test gf_isom_set_traf_base_media_decode_time
    gf_isom_set_traf_base_media_decode_time(isom_file, trackID, decode_time);

    // Test gf_isom_patch_last_sample_duration
    gf_isom_patch_last_sample_duration(isom_file, trackNumber, next_dts);

    // Test gf_isom_set_media_creation_time
    gf_isom_set_media_creation_time(isom_file, trackNumber, create_time, modif_time);

    // Test gf_isom_force_track_duration
    gf_isom_force_track_duration(isom_file, trackNumber, duration);

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

        LLVMFuzzerTestOneInput_204(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    