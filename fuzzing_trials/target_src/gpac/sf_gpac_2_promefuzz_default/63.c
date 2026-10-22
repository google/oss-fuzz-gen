// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_data_offset_63 at isom_read.c:3151:8 in isomedia.h
// gf_isom_remove_edits at isom_write.c:2916:8 in isomedia.h
// gf_isom_get_edit at isom_read.c:2560:8 in isomedia.h
// gf_isom_update_sample_reference at isom_write.c:1538:8 in isomedia.h
// gf_isom_remove_stream_description at isom_write.c:970:8 in isomedia.h
// gf_isom_add_sample_info at isom_write.c:7791:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void test_gf_isom_reset_data_offset_63(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    u64 top_box_start;
    if (Size >= sizeof(u64)) {
        memcpy(&top_box_start, Data, sizeof(u64));
    } else {
        top_box_start = 0;
    }
    gf_isom_reset_data_offset(isom_file, &top_box_start);
}

static void test_gf_isom_remove_edits(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(u32)) {
        u32 trackNumber;
        memcpy(&trackNumber, Data, sizeof(u32));
        gf_isom_remove_edits(isom_file, trackNumber);
    }
}

static void test_gf_isom_get_edit(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size >= 3 * sizeof(u32) + 4 * sizeof(u64)) {
        u32 trackNumber, EditIndex;
        u64 EditTime, SegmentDuration, MediaTime;
        GF_ISOEditType EditMode;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&EditIndex, Data + sizeof(u32), sizeof(u32));
        gf_isom_get_edit(isom_file, trackNumber, EditIndex, &EditTime, &SegmentDuration, &MediaTime, &EditMode);
    }
}

static void test_gf_isom_update_sample_reference(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size >= 3 * sizeof(u32) + sizeof(u64)) {
        u32 trackNumber, sampleNumber;
        u64 data_offset;
        GF_ISOSample sample;
        memset(&sample, 0, sizeof(GF_ISOSample)); // Initialize sample
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&sampleNumber, Data + sizeof(u32), sizeof(u32));
        memcpy(&data_offset, Data + 2 * sizeof(u32), sizeof(u64));
        gf_isom_update_sample_reference(isom_file, trackNumber, sampleNumber, &sample, data_offset);
    }
}

static void test_gf_isom_remove_stream_description(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size >= 2 * sizeof(u32)) {
        u32 trackNumber, sampleDescriptionIndex;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&sampleDescriptionIndex, Data + sizeof(u32), sizeof(u32));
        gf_isom_remove_stream_description(isom_file, trackNumber, sampleDescriptionIndex);
    }
}

static void test_gf_isom_add_sample_info(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size >= 5 * sizeof(u32)) {
        u32 trackNumber, sampleNumber, grouping_type, sampleGroupDescriptionIndex, grouping_type_parameter;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&sampleNumber, Data + sizeof(u32), sizeof(u32));
        memcpy(&grouping_type, Data + 2 * sizeof(u32), sizeof(u32));
        memcpy(&sampleGroupDescriptionIndex, Data + 3 * sizeof(u32), sizeof(u32));
        memcpy(&grouping_type_parameter, Data + 4 * sizeof(u32), sizeof(u32));
        gf_isom_add_sample_info(isom_file, trackNumber, sampleNumber, grouping_type, sampleGroupDescriptionIndex, grouping_type_parameter);
    }
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0; // If file can't be opened, exit early

    test_gf_isom_reset_data_offset_63(isom_file, Data, Size);
    test_gf_isom_remove_edits(isom_file, Data, Size);
    test_gf_isom_get_edit(isom_file, Data, Size);
    test_gf_isom_update_sample_reference(isom_file, Data, Size);
    test_gf_isom_remove_stream_description(isom_file, Data, Size);
    test_gf_isom_add_sample_info(isom_file, Data, Size);

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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    