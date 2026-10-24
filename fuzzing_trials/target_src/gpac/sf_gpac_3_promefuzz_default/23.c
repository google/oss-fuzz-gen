// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_remove_cenc_seig_sample_group at drm_sample.c:1037:8 in isomedia.h
// gf_isom_remove_track_references at isom_write.c:5155:8 in isomedia.h
// gf_isom_remove_cenc_senc_box at drm_sample.c:996:8 in isomedia.h
// gf_isom_sdp_clean_track at hint_track.c:790:8 in isomedia.h
// gf_isom_cenc_allocate_storage at drm_sample.c:1142:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void initialize_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char *dummy_data = "dummy data";
        fwrite(dummy_data, 1, sizeof(dummy_data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    initialize_dummy_file();

    // Open the ISO file using gpac API, which will internally allocate the GF_ISOFile structure
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = 0;
    if (Size >= sizeof(u32)) {
        trackNumber = *(u32 *)Data;
    }

    gf_isom_remove_cenc_seig_sample_group(isom_file, trackNumber);
    gf_isom_remove_track_references(isom_file, trackNumber);
    gf_isom_remove_cenc_senc_box(isom_file, trackNumber);
    gf_isom_sdp_clean_track(isom_file, trackNumber);
    gf_isom_cenc_allocate_storage(isom_file, trackNumber);

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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    