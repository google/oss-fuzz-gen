// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_meta_add_item_ref at meta.c:2005:8 in isomedia.h
// gf_isom_meta_add_item_ref at meta.c:2005:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_edit at isom_read.c:2560:8 in isomedia.h
// gf_isom_check_data_reference at isom_read.c:1705:8 in isomedia.h
// gf_isom_remove_stream_description at isom_write.c:970:8 in isomedia.h
// gf_isom_update_sample_reference at isom_write.c:1538:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 4 + sizeof(u64)) {
        return 0;
    }

    // Initialize the isom_file as NULL since we don't have the full struct definition
    GF_ISOFile *isom_file = NULL;

    u64 ref_index = 0;
    u64 top_box_start = 0;
    u64 EditTime = 0, SegmentDuration = 0, MediaTime = 0;
    GF_ISOEditType EditMode;
    GF_ISOSample *sample = NULL;

    u32 from_id = *(u32 *)Data;
    u32 to_id = *(u32 *)(Data + 4);
    u32 type = *(u32 *)(Data + 8);
    u32 trackNumber = *(u32 *)(Data + 12);
    u32 sampleDescriptionIndex = *(u32 *)(Data + 16);
    u32 sampleNumber = *(u32 *)(Data + 20);

    // Write dummy data to a file if needed
    write_dummy_file(Data, Size);

    // Fuzz gf_isom_meta_add_item_ref
    gf_isom_meta_add_item_ref(isom_file, GF_TRUE, 0, from_id, to_id, type, &ref_index);
    gf_isom_meta_add_item_ref(isom_file, GF_FALSE, trackNumber, from_id, to_id, type, &ref_index);

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Fuzz gf_isom_get_edit
    gf_isom_get_edit(isom_file, trackNumber, 1, &EditTime, &SegmentDuration, &MediaTime, &EditMode);

    // Fuzz gf_isom_check_data_reference
    gf_isom_check_data_reference(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_remove_stream_description
    gf_isom_remove_stream_description(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_update_sample_reference
    gf_isom_update_sample_reference(isom_file, trackNumber, sampleNumber, sample, 0);

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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    