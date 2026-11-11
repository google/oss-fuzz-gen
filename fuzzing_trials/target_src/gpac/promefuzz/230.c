// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_meta_image_props at meta.c:735:8 in isomedia.h
// gf_isom_dump_supported_box at box_funcs.c:2293:8 in isomedia.h
// gf_isom_text_dump at box_dump.c:4470:8 in isomedia.h
// gf_isom_get_sample_for_media_time at isom_read.c:2192:8 in isomedia.h
// gf_isom_set_nalu_extract_mode at isom_read.c:5481:8 in isomedia.h
// gf_isom_add_sample_reference at isom_write.c:1269:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void fuzz_gf_isom_get_meta_image_props(GF_ISOFile *isom_file) {
    Bool root_meta = rand() % 2;
    u32 track_num = rand() % 10;
    u32 item_id = rand() % 100;
    GF_ImageItemProperties out_image_props;
    GF_List *unmapped_props = NULL;

    gf_isom_get_meta_image_props(isom_file, root_meta, track_num, item_id, &out_image_props, unmapped_props);
}

static void fuzz_gf_isom_dump_supported_box() {
    FILE *trace = fopen("./dummy_file", "wb");
    if (!trace) return;

    u32 idx = rand() % 100;
    gf_isom_dump_supported_box(idx, trace);

    fclose(trace);
}

static void fuzz_gf_isom_text_dump(GF_ISOFile *isom_file) {
    FILE *dump = fopen("./dummy_file", "wb");
    if (!dump) return;

    u32 trackNumber = rand() % 10;
    GF_TextDumpType dump_type = rand() % 3;

    gf_isom_text_dump(isom_file, trackNumber, dump, dump_type);

    fclose(dump);
}

static void fuzz_gf_isom_get_sample_for_media_time(GF_ISOFile *isom_file) {
    u32 trackNumber = rand() % 10;
    u64 desiredTime = rand() % 1000;
    u32 sampleDescriptionIndex;
    GF_ISOSearchMode SearchMode = rand() % 3;
    GF_ISOSample *sample = NULL;
    u32 sample_number;
    u64 data_offset;

    gf_isom_get_sample_for_media_time(isom_file, trackNumber, desiredTime, &sampleDescriptionIndex, SearchMode, &sample, &sample_number, &data_offset);
}

static void fuzz_gf_isom_set_nalu_extract_mode(GF_ISOFile *isom_file) {
    u32 trackNumber = rand() % 10;
    GF_ISONaluExtractMode nalu_extract_mode = rand() % 3;

    gf_isom_set_nalu_extract_mode(isom_file, trackNumber, nalu_extract_mode);
}

static void fuzz_gf_isom_add_sample_reference(GF_ISOFile *isom_file) {
    u32 trackNumber = rand() % 10;
    u32 sampleDescriptionIndex = rand() % 10;
    GF_ISOSample *sample = NULL;
    u64 dataOffset = rand() % 1000;

    gf_isom_add_sample_reference(isom_file, trackNumber, sampleDescriptionIndex, sample, dataOffset);
}

int LLVMFuzzerTestOneInput_230(const uint8_t *Data, size_t Size) {
    // Assuming gf_isom_open and gf_isom_close are functions to handle GF_ISOFile objects.
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    fuzz_gf_isom_get_meta_image_props(isom_file);
    fuzz_gf_isom_dump_supported_box();
    fuzz_gf_isom_text_dump(isom_file);
    fuzz_gf_isom_get_sample_for_media_time(isom_file);
    fuzz_gf_isom_set_nalu_extract_mode(isom_file);
    fuzz_gf_isom_add_sample_reference(isom_file);

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

        LLVMFuzzerTestOneInput_230(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    