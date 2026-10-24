// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_start_fragment at movie_fragments.c:2584:8 in isomedia.h
// gf_isom_sdp_clean at hint_track.c:884:8 in isomedia.h
// gf_isom_reset_alt_brands at isom_write.c:3801:8 in isomedia.h
// gf_isom_enable_compression at isom_write.c:2779:8 in isomedia.h
// gf_isom_remove_user_data at isom_write.c:3877:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return 0;

    // Fuzz gf_isom_close
    gf_isom_close(iso_file);

    // Reopen the file for further operations
    iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return 0;

    // Fuzz gf_isom_start_fragment with boolean flag derived from input
    GF_ISOStartFragmentFlags moof_first = Data[0] % 2;
    gf_isom_start_fragment(iso_file, moof_first);

    // Fuzz gf_isom_sdp_clean
    gf_isom_sdp_clean(iso_file);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(iso_file);

    // Fuzz gf_isom_enable_compression with compress_mode and flags derived from input
    if (Size >= 3) {
        GF_ISOCompressMode compress_mode = Data[1] % 256;
        u32 compress_flags = Data[2];
        gf_isom_enable_compression(iso_file, compress_mode, compress_flags);
    }

    // Fuzz gf_isom_remove_user_data with parameters derived from input
    if (Size >= 19) {
        u32 trackNumber = Data[3];
        u32 UserDataType = Data[4];
        bin128 UUID;
        memcpy(UUID, Data + 5, sizeof(bin128));
        gf_isom_remove_user_data(iso_file, trackNumber, UserDataType, UUID);
    }

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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    