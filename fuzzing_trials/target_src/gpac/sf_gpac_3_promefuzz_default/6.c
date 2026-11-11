// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_start_fragment at movie_fragments.c:2584:8 in isomedia.h
// gf_isom_sdp_clean at hint_track.c:884:8 in isomedia.h
// gf_isom_remove_root_od at isom_write.c:165:8 in isomedia.h
// gf_isom_reset_alt_brands at isom_write.c:3801:8 in isomedia.h
// gf_isom_enable_compression at isom_write.c:2779:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Assuming there is a function to create or open an ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Fuzz gf_isom_close
    gf_isom_close(isom_file);

    // Reopen file for further operations
    isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Fuzz gf_isom_start_fragment
    GF_ISOStartFragmentFlags moof_first = (Size > 0) ? Data[0] % 2 : 0;
    gf_isom_start_fragment(isom_file, moof_first);

    // Fuzz gf_isom_sdp_clean
    gf_isom_sdp_clean(isom_file);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(isom_file);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(isom_file);

    // Fuzz gf_isom_enable_compression
    GF_ISOCompressMode compress_mode = (Size > 1) ? Data[1] % 3 : 0;
    u32 compress_flags = (Size > 2) ? Data[2] : 0;
    gf_isom_enable_compression(isom_file, compress_mode, compress_flags);

    cleanup_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    