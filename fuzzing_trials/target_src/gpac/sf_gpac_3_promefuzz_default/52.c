// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
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
    // Assuming there's a function to create a new GF_ISOFile
    GF_ISOFile* iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    // Fuzz gf_isom_set_image_sequence_coding_constraints
    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = (Size > 1) ? Data[1] : 0;
    Bool remove = (Size > 2) ? Data[2] % 2 : 0;
    Bool all_ref_pics_intra = (Size > 3) ? Data[3] % 2 : 0;
    Bool intra_pred_used = (Size > 4) ? Data[4] % 2 : 0;
    u32 max_ref_per_pic = (Size > 5) ? Data[5] : 0;
    gf_isom_set_image_sequence_coding_constraints(
        iso_file, trackNumber, sampleDescriptionIndex, remove, 
        all_ref_pics_intra, intra_pred_used, max_ref_per_pic);

    // Fuzz gf_isom_reset_alt_brands_ex
    Bool leave_empty = (Size > 6) ? Data[6] % 2 : 0;
    gf_isom_reset_alt_brands_ex(iso_file, leave_empty);

    // Fuzz gf_isom_set_meta_xml
    Bool root_meta = (Size > 7) ? Data[7] % 2 : 0;
    u32 track_num = (Size > 8) ? Data[8] : 0;
    Bool IsBinaryXML = (Size > 9) ? Data[9] % 2 : 0;
    gf_isom_set_meta_xml(iso_file, root_meta, track_num, NULL, (unsigned char*)Data, Size, IsBinaryXML);

    // Fuzz gf_isom_set_movie_duration
    u64 duration = (Size > 10) ? Data[10] : 0;
    Bool remove_mehd = (Size > 11) ? Data[11] % 2 : 0;
    gf_isom_set_movie_duration(iso_file, duration, remove_mehd);

    // Fuzz gf_isom_reset_tables
    Bool reset_sample_count = (Size > 12) ? Data[12] % 2 : 0;
    gf_isom_reset_tables(iso_file, reset_sample_count);

    // Close the ISO file
    gf_isom_close(iso_file);

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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    