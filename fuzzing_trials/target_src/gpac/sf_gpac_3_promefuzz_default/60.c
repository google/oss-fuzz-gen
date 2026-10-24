// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_fragment_set_cenc_sai at movie_fragments.c:3006:8 in isomedia.h
// gf_isom_remove_meta_xml at meta.c:678:8 in isomedia.h
// gf_isom_set_qt_key at isom_write.c:6772:8 in isomedia.h
// gf_isom_text_set_streaming_mode at isom_read.c:3688:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void initialize_iso_file(GF_ISOFile **isom_file) {
    *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    GF_ISOFile *isom_file = NULL;
    initialize_iso_file(&isom_file);
    if (!isom_file) return 0;

    // Prepare a dummy file if needed by the API
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Fuzz gf_isom_release_segment
    Bool reset_tables = Data[0] % 2;
    gf_isom_release_segment(isom_file, reset_tables);

    // Fuzz gf_isom_fragment_set_cenc_sai
    GF_ISOTrackID trackID = (GF_ISOTrackID)(Data[0] % 256);
    u8 *sai_b = Size > 1 ? (u8 *)&Data[1] : NULL;
    u32 sai_b_size = Size > 1 ? Size - 1 : 0;
    Bool use_subsample = Data[0] % 2;
    Bool use_saio_32bit = (Data[0] / 2) % 2;
    Bool use_multikey = (Data[0] / 4) % 2;
    gf_isom_fragment_set_cenc_sai(isom_file, trackID, sai_b, sai_b_size, use_subsample, use_saio_32bit, use_multikey);

    // Fuzz gf_isom_remove_meta_xml
    Bool root_meta = (Data[0] / 8) % 2;
    u32 track_num = (u32)(Data[0] % 256);
    gf_isom_remove_meta_xml(isom_file, root_meta, track_num);

    // Fuzz gf_isom_set_qt_key
    GF_QT_UDTAKey *key = NULL; // Assuming a valid key structure is not necessary for fuzzing purposes
    gf_isom_set_qt_key(isom_file, key);

    // Fuzz gf_isom_text_set_streaming_mode
    Bool do_convert = (Data[0] / 16) % 2;
    gf_isom_text_set_streaming_mode(isom_file, do_convert);

    // Clean up
    cleanup_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    