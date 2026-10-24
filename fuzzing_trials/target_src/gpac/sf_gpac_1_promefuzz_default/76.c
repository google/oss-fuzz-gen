// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_track_kind_count at isom_read.c:1136:5 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_sample_count at isom_read.c:1767:5 in isomedia.h
// gf_isom_get_max_sample_size at isom_read.c:2021:5 in isomedia.h
// gf_isom_get_track_count at isom_read.c:783:5 in isomedia.h
// gf_isom_segment_get_track_fragment_count at isom_read.c:895:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    // Create a dummy ISO file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Initialize a GF_ISOFile pointer
    GF_ISOFile *isom_file = NULL;

    // Fuzz gf_isom_get_track_kind_count
    u32 trackNumber = Size > 0 ? Data[0] : 0;  // Use the first byte of Data as track number if available
    u32 kind_count = gf_isom_get_track_kind_count(isom_file, trackNumber);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_get_sample_count
    u32 sample_count = gf_isom_get_sample_count(isom_file, trackNumber);

    // Fuzz gf_isom_get_max_sample_size
    u32 max_sample_size = gf_isom_get_max_sample_size(isom_file, trackNumber);

    // Fuzz gf_isom_get_track_count
    u32 track_count = gf_isom_get_track_count(isom_file);

    // Fuzz gf_isom_segment_get_track_fragment_count
    u32 moof_index = Size > 1 ? Data[1] : 0;  // Use the second byte of Data as moof index if available
    u32 track_fragment_count = gf_isom_segment_get_track_fragment_count(isom_file, moof_index);

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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    