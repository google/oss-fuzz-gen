// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_track_flags at isom_write.c:277:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_start_fragment at movie_fragments.c:2584:8 in isomedia.h
// gf_isom_sdp_clean at hint_track.c:884:8 in isomedia.h
// gf_isom_reset_alt_brands at isom_write.c:3801:8 in isomedia.h
// gf_isom_enable_compression at isom_write.c:2779:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    // Ensure there is enough data to perform meaningful operations
    if (Size < 6) {
        return 0;
    }

    // Open a dummy ISO file
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) {
        return 0;
    }

    // Fuzz gf_isom_set_track_flags
    u32 trackNumber = Data[0];
    u32 flags = Data[1];
    GF_ISOMTrackFlagOp op = (GF_ISOMTrackFlagOp)(Data[2] % 3); // Assume 3 operations
    gf_isom_set_track_flags(isom_file, trackNumber, flags, op);

    // Fuzz gf_isom_close
    gf_isom_close(isom_file);

    // Reopen the file for further operations
    isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) {
        return 0;
    }

    // Fuzz gf_isom_start_fragment
    GF_ISOStartFragmentFlags moof_first = (GF_ISOStartFragmentFlags)(Data[3] % 2); // Assume 2 possible states
    gf_isom_start_fragment(isom_file, moof_first);

    // Fuzz gf_isom_sdp_clean
    gf_isom_sdp_clean(isom_file);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(isom_file);

    // Fuzz gf_isom_enable_compression
    GF_ISOCompressMode compress_mode = (GF_ISOCompressMode)(Data[4] % 3); // Assume 3 compression modes
    u32 compress_flags = Data[5];
    gf_isom_enable_compression(isom_file, compress_mode, compress_flags);

    // Cleanup
    gf_isom_close(isom_file);

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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    