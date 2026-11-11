// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_image_sequence_coding_constraints at isom_write.c:2412:8 in isomedia.h
// gf_isom_reset_alt_brands_ex at isom_write.c:3765:8 in isomedia.h
// gf_isom_set_meta_xml at meta.c:698:8 in isomedia.h
// gf_isom_set_movie_duration at movie_fragments.c:61:8 in isomedia.h
// gf_isom_reset_tables at isom_read.c:3407:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // Instead, we assume a function or macro initializes it properly.
    // For fuzzing purposes, we simulate this step.
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_EDIT, NULL);
}

static void destroy_dummy_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isoFile = create_dummy_iso_file();
    if (!isoFile) return 0;

    // Fuzz gf_isom_set_image_sequence_coding_constraints
    if (Size >= 6) {
        u32 trackNumber = Data[0];
        u32 sampleDescriptionIndex = Data[1];
        Bool remove = Data[2] % 2;
        Bool all_ref_pics_intra = Data[3] % 2;
        Bool intra_pred_used = Data[4] % 2;
        u32 max_ref_per_pic = Data[5];
        gf_isom_set_image_sequence_coding_constraints(isoFile, trackNumber, sampleDescriptionIndex, remove, all_ref_pics_intra, intra_pred_used, max_ref_per_pic);
    }

    // Fuzz gf_isom_reset_alt_brands_ex
    if (Size >= 7) {
        Bool leave_empty = Data[6] % 2;
        gf_isom_reset_alt_brands_ex(isoFile, leave_empty);
    }

    // Fuzz gf_isom_set_meta_xml
    if (Size >= 8) {
        Bool root_meta = Data[7] % 2;
        u32 track_num = (Size > 8) ? Data[8] : 0;
        char *xmlFileName = NULL;
        unsigned char *data = NULL;
        u32 data_size = 0;
        Bool IsBinaryXML = (Size > 9) ? Data[9] % 2 : 0;
        gf_isom_set_meta_xml(isoFile, root_meta, track_num, xmlFileName, data, data_size, IsBinaryXML);
    }

    // Fuzz gf_isom_set_movie_duration
    if (Size >= 10) {
        u64 duration = (Size > 11) ? *((u64 *)&Data[10]) : 0;
        Bool remove_mehd = (Size > 18) ? Data[18] % 2 : 0;
        gf_isom_set_movie_duration(isoFile, duration, remove_mehd);
    }

    // Fuzz gf_isom_reset_tables
    if (Size >= 19) {
        Bool reset_sample_count = Data[19] % 2;
        gf_isom_reset_tables(isoFile, reset_sample_count);
    }

    // Finally, close the ISO file
    gf_isom_close(isoFile);

    destroy_dummy_iso_file(isoFile);
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

        LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    