// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_image_sequence_coding_constraints at isom_write.c:2412:8 in isomedia.h
// gf_isom_reset_alt_brands_ex at isom_write.c:3765:8 in isomedia.h
// gf_isom_set_meta_xml at meta.c:698:8 in isomedia.h
// gf_isom_set_movie_duration at movie_fragments.c:61:8 in isomedia.h
// gf_isom_reset_tables at isom_read.c:3407:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy GF_ISOFile object
    GF_ISOFile *file = NULL;
    return file;
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize the ISO file
    GF_ISOFile *isoFile = create_dummy_iso_file();
    if (!isoFile) return 0;

    // Use the data to perform various operations
    u32 trackNumber = Data[0] % 100;  // Simulate track number
    u32 sampleDescriptionIndex = Data[0] % 10;  // Simulate sample description index
    Bool remove = Data[0] % 2;
    Bool all_ref_pics_intra = (Data[0] >> 1) % 2;
    Bool intra_pred_used = (Data[0] >> 2) % 2;
    u32 max_ref_per_pic = Data[0] % 5;

    // Call the function to set image sequence coding constraints
    gf_isom_set_image_sequence_coding_constraints(isoFile, trackNumber, sampleDescriptionIndex, remove, all_ref_pics_intra, intra_pred_used, max_ref_per_pic);

    // Reset alternate brands
    Bool leave_empty = Data[0] % 2;
    gf_isom_reset_alt_brands_ex(isoFile, leave_empty);

    // Set meta XML
    Bool root_meta = Data[0] % 2;
    u32 track_num = Data[0] % 100;
    Bool IsBinaryXML = Data[0] % 2;
    gf_isom_set_meta_xml(isoFile, root_meta, track_num, NULL, (unsigned char *)Data, (u32)Size, IsBinaryXML);

    // Set movie duration
    u64 duration = (u64)Size;
    Bool remove_mehd = Data[0] % 2;
    gf_isom_set_movie_duration(isoFile, duration, remove_mehd);

    // Reset tables
    Bool reset_sample_count = Data[0] % 2;
    gf_isom_reset_tables(isoFile, reset_sample_count);

    // Close the ISO file
    gf_isom_close(isoFile);

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

        LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    