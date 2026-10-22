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
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocating a dummy GF_ISOFile structure
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_dummy_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file if required by the API
    FILE *dummyFile = fopen("./dummy_file", "wb");
    if (dummyFile) {
        fwrite(Data, 1, Size, dummyFile);
        fclose(dummyFile);
    }

    GF_ISOFile *isoFile = create_dummy_iso_file();

    if (!isoFile) return 0;

    // Fuzz gf_isom_close
    gf_isom_close(isoFile);

    // Reopen the file for further operations
    isoFile = create_dummy_iso_file();
    if (!isoFile) return 0;

    // Fuzz gf_isom_start_fragment with a boolean flag derived from input
    GF_ISOStartFragmentFlags moof_first = Data[0] % 2;
    gf_isom_start_fragment(isoFile, moof_first);

    // Fuzz gf_isom_sdp_clean
    gf_isom_sdp_clean(isoFile);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(isoFile);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(isoFile);

    // Fuzz gf_isom_enable_compression with dummy compression mode and flags
    GF_ISOCompressMode compress_mode = (GF_ISOCompressMode)(Data[0] % 3);
    u32 compress_flags = (Size > 1) ? Data[1] : 0;
    gf_isom_enable_compression(isoFile, compress_mode, compress_flags);

    cleanup_dummy_iso_file(isoFile);

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    