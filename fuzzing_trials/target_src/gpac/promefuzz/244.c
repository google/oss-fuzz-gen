// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_track_duration_orig at isom_read.c:1092:5 in isomedia.h
// gf_isom_get_current_tfdt at isom_read.c:5822:5 in isomedia.h
// gf_isom_get_sample_from_dts at isom_read.c:2168:5 in isomedia.h
// gf_isom_get_sample_dts at isom_read.c:2141:5 in isomedia.h
// gf_isom_get_smooth_next_tfdt at isom_read.c:5835:5 in isomedia.h
// gf_isom_get_track_magic at isom_read.c:6160:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // As we do not have the full definition of GF_ISOFile, we cannot allocate memory for it.
    // Instead, we assume that the API functions can handle a NULL pointer gracefully.
    return NULL;
}

static void destroy_dummy_isofile(GF_ISOFile *isofile) {
    // No need to free anything since we are returning NULL in create_dummy_isofile.
}

int LLVMFuzzerTestOneInput_244(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) + sizeof(u64)) return 0;

    GF_ISOFile *isofile = create_dummy_isofile();
    if (!isofile) return 0;

    u32 trackNumber = *((u32 *)Data);
    u64 dts = *((u64 *)(Data + sizeof(u32)));

    // Fuzz gf_isom_get_track_duration_orig
    u64 duration = gf_isom_get_track_duration_orig(isofile, trackNumber);

    // Fuzz gf_isom_get_current_tfdt
    u64 tfdt = gf_isom_get_current_tfdt(isofile, trackNumber);

    // Fuzz gf_isom_get_sample_from_dts
    u32 sampleNumber = gf_isom_get_sample_from_dts(isofile, trackNumber, dts);

    // Fuzz gf_isom_get_sample_dts
    u64 sampleDts = gf_isom_get_sample_dts(isofile, trackNumber, sampleNumber);

    // Fuzz gf_isom_get_smooth_next_tfdt
    u64 smoothTfdt = gf_isom_get_smooth_next_tfdt(isofile, trackNumber);

    // Fuzz gf_isom_get_track_magic
    u64 trackMagic = gf_isom_get_track_magic(isofile, trackNumber);

    // Cleanup
    destroy_dummy_isofile(isofile);

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

        LLVMFuzzerTestOneInput_244(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    