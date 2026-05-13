// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_max_sample_cts_offset at isom_read.c:2070:5 in isomedia.h
// gf_isom_get_decoder_config at isom_read.c:1406:19 in isomedia.h
// gf_isom_get_mpeg4_subtype at isom_read.c:1671:5 in isomedia.h
// gf_isom_get_track_original_id at isom_read.c:824:15 in isomedia.h
// gf_isom_segment_get_track_fragment_count at isom_read.c:895:5 in isomedia.h
// gf_isom_get_constant_sample_duration at isom_read.c:1789:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_256(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = Data[1];
    u32 moof_index = Data[2];

    // Test gf_isom_get_max_sample_cts_offset
    u32 max_cts_offset = gf_isom_get_max_sample_cts_offset(isom_file, trackNumber);

    // Test gf_isom_get_decoder_config
    GF_DecoderConfig *decoderConfig = gf_isom_get_decoder_config(isom_file, trackNumber, sampleDescriptionIndex);
    if (decoderConfig) {
        gf_odf_desc_del((GF_Descriptor *)decoderConfig);
    }

    // Test gf_isom_get_mpeg4_subtype
    u32 mpeg4_subtype = gf_isom_get_mpeg4_subtype(isom_file, trackNumber, sampleDescriptionIndex);

    // Test gf_isom_get_track_original_id
    GF_ISOTrackID original_track_id = gf_isom_get_track_original_id(isom_file, trackNumber);

    // Test gf_isom_segment_get_track_fragment_count
    u32 fragment_count = gf_isom_segment_get_track_fragment_count(isom_file, moof_index);

    // Test gf_isom_get_constant_sample_duration
    u32 constant_sample_duration = gf_isom_get_constant_sample_duration(isom_file, trackNumber);

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

        LLVMFuzzerTestOneInput_256(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    