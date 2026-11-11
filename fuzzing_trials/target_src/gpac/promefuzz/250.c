// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_missing_bytes at isom_read.c:2482:5 in isomedia.h
// gf_isom_get_media_original_duration at isom_read.c:1448:5 in isomedia.h
// gf_isom_get_current_tfdt at isom_read.c:5822:5 in isomedia.h
// gf_isom_get_track_duration at isom_read.c:1076:5 in isomedia.h
// gf_isom_get_track_magic at isom_read.c:6160:5 in isomedia.h
// gf_isom_get_media_data_size at isom_read.c:4131:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Since we can't allocate a struct with incomplete type, return NULL
    return NULL;
}

static void destroy_dummy_isofile(GF_ISOFile *file) {
    // Nothing to free since we return NULL in create_dummy_isofile
}

int LLVMFuzzerTestOneInput_250(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;

    // Fuzz gf_isom_get_missing_bytes
    u64 missing_bytes = gf_isom_get_missing_bytes(isom_file, trackNumber);
    (void)missing_bytes;

    // Fuzz gf_isom_get_media_original_duration
    u64 original_duration = gf_isom_get_media_original_duration(isom_file, trackNumber);
    (void)original_duration;

    // Fuzz gf_isom_get_current_tfdt
    u64 current_tfdt = gf_isom_get_current_tfdt(isom_file, trackNumber);
    (void)current_tfdt;

    // Fuzz gf_isom_get_track_duration
    u64 track_duration = gf_isom_get_track_duration(isom_file, trackNumber);
    (void)track_duration;

    // Fuzz gf_isom_get_track_magic
    u64 track_magic = gf_isom_get_track_magic(isom_file, trackNumber);
    (void)track_magic;

    // Fuzz gf_isom_get_media_data_size
    u64 media_data_size = gf_isom_get_media_data_size(isom_file, trackNumber);
    (void)media_data_size;

    destroy_dummy_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_250(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    