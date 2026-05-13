// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_needs_layer_reconstruction at isom_read.c:5516:6 in isomedia.h
// gf_isom_moov_first at isom_read.c:4964:6 in isomedia.h
// gf_isom_is_smooth_streaming_moov at isom_read.c:5848:6 in isomedia.h
// gf_isom_has_movie at isom_read.c:835:6 in isomedia.h
// gf_isom_is_single_av at isom_read.c:4218:6 in isomedia.h
// gf_isom_disable_odf_conversion at isom_read.c:652:6 in isomedia.h
// gf_isom_disable_odf_conversion at isom_read.c:652:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file(const uint8_t *Data, size_t Size) {
    // Assuming GF_ISOFile is properly initialized elsewhere
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return NULL;

    // Simulate file content if needed for fuzzing
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    return isom_file;
}

static void destroy_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_264(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_iso_file(Data, Size);
    if (!isom_file) return 0;

    // Invoke the target functions with the dummy ISO file
    Bool needs_reconstruction = gf_isom_needs_layer_reconstruction(isom_file);
    Bool moov_first = gf_isom_moov_first(isom_file);
    Bool is_smooth = gf_isom_is_smooth_streaming_moov(isom_file);
    Bool has_movie = gf_isom_has_movie(isom_file);
    Bool is_single_av = gf_isom_is_single_av(isom_file);

    // Test gf_isom_disable_odf_conversion with both TRUE and FALSE
    gf_isom_disable_odf_conversion(isom_file, GF_TRUE);
    gf_isom_disable_odf_conversion(isom_file, GF_FALSE);

    // Cleanup
    destroy_dummy_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_264(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    