// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_iamf_config_new at avc_ext.c:2083:8 in isomedia.h
// gf_isom_set_media_language at isom_write.c:297:8 in isomedia.h
// gf_isom_new_mpha_description at sample_descs.c:1879:8 in isomedia.h
// gf_isom_flac_config_new at sample_descs.c:839:8 in isomedia.h
// gf_isom_set_adobe_protection at drm_sample.c:1846:8 in isomedia.h
// gf_isom_get_data_reference at isom_read.c:1723:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
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

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 15 * sizeof(u32)) {
        return 0; // Not enough data to proceed
    }

    // Prepare a dummy ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    // Prepare trackNumber, URLname, URNname, and outDescriptionIndex
    u32 trackNumber = *(u32 *)Data;
    const char *URLname = (const char *)(Data + sizeof(u32));
    const char *URNname = (const char *)(Data + 2 * sizeof(u32));
    u32 outDescriptionIndex;

    // Prepare a dummy IAMF config
    GF_IAConfig *cfg = (GF_IAConfig *)malloc(sizeof(GF_IAConfig));
    if (!cfg) {
        gf_isom_close(isom_file);
        return 0;
    }
    memset(cfg, 0, sizeof(GF_IAConfig));

    // Call the target function gf_isom_iamf_config_new
    gf_isom_iamf_config_new(isom_file, trackNumber, cfg, URLname, URNname, &outDescriptionIndex);

    // Prepare language code for gf_isom_set_media_language
    char *language_code = (char *)(Data + 3 * sizeof(u32));
    gf_isom_set_media_language(isom_file, trackNumber, language_code);

    // Prepare data for gf_isom_new_mpha_description
    u8 *dsi = (u8 *)(Data + 4 * sizeof(u32));
    u32 dsi_size = *(u32 *)(Data + 5 * sizeof(u32));
    u32 mha_subtype = *(u32 *)(Data + 6 * sizeof(u32));
    gf_isom_new_mpha_description(isom_file, trackNumber, URLname, URNname, &outDescriptionIndex, dsi, dsi_size, mha_subtype);

    // Prepare metadata for gf_isom_flac_config_new
    u8 *metadata = (u8 *)(Data + 7 * sizeof(u32));
    u32 metadata_size = *(u32 *)(Data + 8 * sizeof(u32));
    gf_isom_flac_config_new(isom_file, trackNumber, metadata, metadata_size, URLname, URNname, &outDescriptionIndex);

    // Prepare data for gf_isom_set_adobe_protection
    u32 sampleDescriptionIndex = *(u32 *)(Data + 9 * sizeof(u32));
    u32 scheme_type = *(u32 *)(Data + 10 * sizeof(u32));
    u32 scheme_version = *(u32 *)(Data + 11 * sizeof(u32));
    Bool is_selective_enc = *(Bool *)(Data + 12 * sizeof(u32));
    char *metadata_adobe = (char *)(Data + 13 * sizeof(u32));
    u32 len = *(u32 *)(Data + 14 * sizeof(u32));
    gf_isom_set_adobe_protection(isom_file, trackNumber, sampleDescriptionIndex, scheme_type, scheme_version, is_selective_enc, metadata_adobe, len);

    // Prepare output pointers for gf_isom_get_data_reference
    const char *outURL = NULL;
    const char *outURN = NULL;
    gf_isom_get_data_reference(isom_file, trackNumber, sampleDescriptionIndex, &outURL, &outURN);

    // Cleanup
    free(cfg);
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    