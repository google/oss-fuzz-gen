#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void fuzz_gf_isom_enum_sample_aux_data(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 12) return; // Ensure enough data for parameters

    u32 trackNumber = *(u32*)Data;
    u32 sample_number = *(u32*)(Data + 4);
    u32 sai_idx = 0;
    u32 sai_type;
    u32 sai_parameter;
    u8 *sai_data = NULL;
    u32 sai_size;

    GF_Err err = gf_isom_enum_sample_aux_data(isom_file, trackNumber, sample_number, &sai_idx, &sai_type, &sai_parameter, &sai_data, &sai_size);
    if (sai_data) free(sai_data);
}

static void fuzz_gf_isom_set_media_type(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 8) return; // Ensure enough data for parameters

    u32 trackNumber = *(u32*)Data;
    u32 new_type = *(u32*)(Data + 4);

    gf_isom_set_media_type(isom_file, trackNumber, new_type);
}

static void fuzz_gf_isom_remove_uuid(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 20) return; // Ensure enough data for parameters

    u32 trackNumber = *(u32*)Data;
    bin128 UUID;
    memcpy(UUID, Data + 4, 16);

    gf_isom_remove_uuid(isom_file, trackNumber, UUID);
}

static void fuzz_gf_isom_get_raw_user_data(GF_ISOFile *isom_file) {
    u8 *output = NULL;
    u32 output_size;

    GF_Err err = gf_isom_get_raw_user_data(isom_file, &output, &output_size);
    if (output) free(output);
}

static void fuzz_gf_isom_text_get_encoded_tx3g(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 12) return; // Ensure enough data for parameters

    u32 trackNumber = *(u32*)Data;
    u32 sampleDescriptionIndex = *(u32*)(Data + 4);
    u32 sidx_offset = *(u32*)(Data + 8);

    u8 *tx3g = NULL;
    u32 tx3g_size;

    GF_Err err = gf_isom_text_get_encoded_tx3g(isom_file, trackNumber, sampleDescriptionIndex, sidx_offset, &tx3g, &tx3g_size);
    if (tx3g) free(tx3g);
}

static void fuzz_gf_isom_sdp_clean_track(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure enough data for parameters

    u32 trackNumber = *(u32*)Data;

    gf_isom_sdp_clean_track(isom_file, trackNumber);
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    fuzz_gf_isom_enum_sample_aux_data(isom_file, Data, Size);
    fuzz_gf_isom_set_media_type(isom_file, Data, Size);
    fuzz_gf_isom_remove_uuid(isom_file, Data, Size);
    fuzz_gf_isom_get_raw_user_data(isom_file);
    fuzz_gf_isom_text_get_encoded_tx3g(isom_file, Data, Size);
    fuzz_gf_isom_sdp_clean_track(isom_file, Data, Size);

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
