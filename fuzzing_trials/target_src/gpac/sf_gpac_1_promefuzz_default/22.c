// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_is_smooth_streaming_moov at isom_read.c:5848:6 in isomedia.h
// gf_isom_is_single_av at isom_read.c:4218:6 in isomedia.h
// gf_isom_get_root_sidx_offsets at isom_read.c:6083:6 in isomedia.h
// gf_isom_set_single_moof_mode at isom_read.c:3144:6 in isomedia.h
// gf_isom_is_inplace_rewrite at isom_write.c:9154:6 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    // Create a dummy file to simulate an ISO file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Open the dummy file as a GF_ISOFile
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Call gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Call gf_isom_is_smooth_streaming_moov
    Bool is_smooth = gf_isom_is_smooth_streaming_moov(isom_file);

    // Call gf_isom_is_single_av
    Bool is_single_av = gf_isom_is_single_av(isom_file);

    // Call gf_isom_get_root_sidx_offsets
    u64 start_offset = 0, end_offset = 0;
    Bool has_sidx = gf_isom_get_root_sidx_offsets(isom_file, &start_offset, &end_offset);

    // Call gf_isom_set_single_moof_mode
    if (Size > 0) {
        Bool mode = Data[0] % 2;
        gf_isom_set_single_moof_mode(isom_file, mode);
    }

    // Call gf_isom_is_inplace_rewrite
    Bool inplace_rewrite = gf_isom_is_inplace_rewrite(isom_file);

    // Close the ISO file
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    