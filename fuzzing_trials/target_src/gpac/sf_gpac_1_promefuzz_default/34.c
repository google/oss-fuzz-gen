// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_is_smooth_streaming_moov at isom_read.c:5848:6 in isomedia.h
// gf_isom_is_single_av at isom_read.c:4218:6 in isomedia.h
// gf_isom_enable_raw_pack at isom_read.c:1799:6 in isomedia.h
// gf_isom_set_single_moof_mode at isom_read.c:3144:6 in isomedia.h
// gf_isom_is_inplace_rewrite at isom_write.c:9154:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Allocate memory for the GF_ISOFile structure
    GF_ISOFile *isofile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isofile;
}

static void cleanup_isofile(GF_ISOFile *isofile) {
    if (isofile) {
        gf_isom_close(isofile);
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isofile = create_dummy_isofile();
    if (!isofile) return 0;

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isofile);
    
    // Fuzz gf_isom_is_smooth_streaming_moov
    Bool isSmooth = gf_isom_is_smooth_streaming_moov(isofile);
    
    // Fuzz gf_isom_is_single_av
    Bool isSingleAV = gf_isom_is_single_av(isofile);
    
    // Fuzz gf_isom_enable_raw_pack
    u32 trackNumber = (Size > 0) ? Data[0] : 0;
    u32 packNumSamples = (Size > 1) ? Data[1] : 1;
    Bool rawPackEnabled = gf_isom_enable_raw_pack(isofile, trackNumber, packNumSamples);
    
    // Fuzz gf_isom_set_single_moof_mode
    Bool mode = (Size > 2) ? Data[2] % 2 : 0;
    gf_isom_set_single_moof_mode(isofile, mode);
    
    // Fuzz gf_isom_is_inplace_rewrite
    Bool isInplaceRewrite = gf_isom_is_inplace_rewrite(isofile);
    
    cleanup_isofile(isofile);
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    