// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_dovi_config_get at avc_ext.c:2654:36 in isomedia.h
// gf_isom_get_track_flags at isom_read.c:1064:5 in isomedia.h
// gf_isom_get_chunk_info at isom_read.c:6325:8 in isomedia.h
// gf_isom_new_track at isom_write.c:863:5 in isomedia.h
// gf_isom_set_nalu_length_field at isom_write.c:8502:8 in isomedia.h
// gf_isom_set_dolby_vision_profile at isom_write.c:1951:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for basic operations

    // Write data to a dummy file to simulate an ISO file
    write_dummy_file(Data, Size);

    // Open the dummy file as an ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Extract some parameters from the input data
    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = Data[1];
    u32 chunkNumber = Data[2];
    u32 nalu_size_length = Data[3];

    // Fuzz gf_isom_dovi_config_get
    GF_DOVIDecoderConfigurationRecord *dovi_config = gf_isom_dovi_config_get(isom_file, trackNumber, sampleDescriptionIndex);
    if (dovi_config) {
        // Simulate deletion of the DOVI config
        free(dovi_config);
    }

    // Fuzz gf_isom_get_track_flags
    u32 track_flags = gf_isom_get_track_flags(isom_file, trackNumber);

    // Fuzz gf_isom_get_chunk_info
    u64 chunk_offset;
    u32 first_sample_num, sample_per_chunk, sample_desc_idx, cache_1 = 0, cache_2 = 0;
    GF_Err chunk_info_err = gf_isom_get_chunk_info(isom_file, trackNumber, chunkNumber, &chunk_offset, &first_sample_num, &sample_per_chunk, &sample_desc_idx, &cache_1, &cache_2);

    // Fuzz gf_isom_new_track
    u32 new_track = gf_isom_new_track(isom_file, 0, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_set_nalu_length_field
    GF_Err nalu_err = gf_isom_set_nalu_length_field(isom_file, trackNumber, sampleDescriptionIndex, nalu_size_length);

    // Fuzz gf_isom_set_dolby_vision_profile
    GF_Err dolby_vision_err = gf_isom_set_dolby_vision_profile(isom_file, trackNumber, sampleDescriptionIndex, dovi_config);

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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    