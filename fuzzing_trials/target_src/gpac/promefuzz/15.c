// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_brand_info at isom_read.c:2631:8 in isomedia.h
// gf_isom_text_get_encoded_tx3g at tx3g.c:950:8 in isomedia.h
// gf_isom_add_uuid at isom_write.c:6258:8 in isomedia.h
// gf_isom_cenc_get_sample_aux_info at drm_sample.c:1645:8 in isomedia.h
// gf_isom_sample_get_subsamples_buffer at isom_read.c:4866:5 in isomedia.h
// gf_isom_get_mpegh_compatible_profiles at isom_read.c:6215:11 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Adjusted to include the third argument for the gf_isom_open function
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
}

static void free_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(bin128)) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 brand = 0, minorVersion = 0, AlternateBrandsCount = 0;
    u32 trackNumber = 0, sampleDescriptionIndex = 0, sidx_offset = 0;
    u8 *tx3g = NULL;
    u32 tx3g_size = 0;
    bin128 UUID;
    const u8 *data = Data;
    u32 dataSize = Size;
    u8 *out_buffer = NULL;
    u32 outSize = 0;
    u32 container_type = 0;
    u32 osize = 0;
    u32 nb_compatible_profiles = 0;

    // Fuzz gf_isom_get_brand_info
    gf_isom_get_brand_info(isom_file, &brand, &minorVersion, &AlternateBrandsCount);

    // Fuzz gf_isom_text_get_encoded_tx3g
    gf_isom_text_get_encoded_tx3g(isom_file, trackNumber, sampleDescriptionIndex, sidx_offset, &tx3g, &tx3g_size);
    free(tx3g);

    // Fuzz gf_isom_add_uuid
    memcpy(UUID, Data, sizeof(bin128));
    gf_isom_add_uuid(isom_file, trackNumber, UUID, data, dataSize);

    // Fuzz gf_isom_cenc_get_sample_aux_info
    gf_isom_cenc_get_sample_aux_info(isom_file, trackNumber, sampleDescriptionIndex, sampleDescriptionIndex, &container_type, &out_buffer, &outSize);
    free(out_buffer);

    // Fuzz gf_isom_sample_get_subsamples_buffer
    u8 *subsamples_buffer = gf_isom_sample_get_subsamples_buffer(isom_file, trackNumber, sampleDescriptionIndex, &osize);
    free(subsamples_buffer);

    // Fuzz gf_isom_get_mpegh_compatible_profiles
    const u8 *profiles = gf_isom_get_mpegh_compatible_profiles(isom_file, trackNumber, sampleDescriptionIndex, &nb_compatible_profiles);

    free_dummy_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    