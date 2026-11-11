// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_max_sample_delta at isom_read.c:2043:5 in isomedia.h
// gf_isom_get_payt_count at hint_track.c:968:5 in isomedia.h
// gf_isom_get_sync_point_count at isom_read.c:2618:5 in isomedia.h
// gf_isom_iamf_config_get at avc_ext.c:2668:14 in isomedia.h
// gf_isom_get_media_timescale at isom_read.c:1459:5 in isomedia.h
// gf_isom_get_constant_sample_size at isom_read.c:1780:5 in isomedia.h
// gf_isom_get_max_sample_delta at isom_read.c:2043:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *data, size_t size) {
    // Create a dummy file to simulate an ISO file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(data, 1, size, file);
    fclose(file);
    
    // Open the dummy file as a GF_ISOFile
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_216(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) return 0;

    u32 trackNumber = *(const u32 *)Data;
    u32 sampleDescriptionIndex = *(const u32 *)(Data + sizeof(u32));
    u32 extraValue = *(const u32 *)(Data + 2 * sizeof(u32));

    // Fuzz gf_isom_get_max_sample_delta
    u32 max_sample_delta = gf_isom_get_max_sample_delta(iso_file, trackNumber);

    // Fuzz gf_isom_get_payt_count
    u32 payt_count = gf_isom_get_payt_count(iso_file, trackNumber);

    // Fuzz gf_isom_get_sync_point_count
    u32 sync_point_count = gf_isom_get_sync_point_count(iso_file, trackNumber);

    // Fuzz gf_isom_iamf_config_get
    GF_IAConfig* iamf_config = gf_isom_iamf_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (iamf_config) {
        // Assume there's a function to free GF_IAConfig
        free(iamf_config);
    }

    // Fuzz gf_isom_get_media_timescale
    u32 media_timescale = gf_isom_get_media_timescale(iso_file, trackNumber);

    // Fuzz gf_isom_get_constant_sample_size
    u32 constant_sample_size = gf_isom_get_constant_sample_size(iso_file, trackNumber);

    // Use extraValue in some way to explore more states
    u32 another_sample_delta = gf_isom_get_max_sample_delta(iso_file, extraValue);

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

        LLVMFuzzerTestOneInput_216(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    