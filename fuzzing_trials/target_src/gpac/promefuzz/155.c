// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_avs3v_config_new at avc_ext.c:2045:8 in isomedia.h
// gf_isom_get_xml_metadata_description at sample_descs.c:1166:8 in isomedia.h
// gf_isom_sdp_get at hint_track.c:909:8 in isomedia.h
// gf_isom_new_stxt_description at sample_descs.c:1418:8 in isomedia.h
// gf_isom_new_webvtt_description at sample_descs.c:1637:8 in isomedia.h
// gf_isom_set_generic_protection at drm_sample.c:626:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile *create_iso_file() {
    // Since GF_ISOFile is an incomplete type, allocate memory for it dynamically
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_EDIT, NULL);
}

static GF_AVS3VConfig *create_avs3v_config() {
    GF_AVS3VConfig *config = malloc(sizeof(GF_AVS3VConfig));
    if (config) {
        memset(config, 0, sizeof(GF_AVS3VConfig));
    }
    return config;
}

int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *iso_file = create_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 outDescriptionIndex;
    GF_AVS3VConfig *avs3v_config = create_avs3v_config();

    // Fuzzing gf_isom_new_webvtt_description
    gf_isom_new_webvtt_description(iso_file, trackNumber, NULL, NULL, &outDescriptionIndex, (const char *)Data);

    // Fuzzing gf_isom_set_generic_protection
    gf_isom_set_generic_protection(iso_file, trackNumber, outDescriptionIndex, 'iAEC', 1, NULL, NULL);

    // Fuzzing gf_isom_sdp_get
    const char *sdp;
    u32 sdp_length;
    gf_isom_sdp_get(iso_file, &sdp, &sdp_length);

    // Fuzzing gf_isom_new_stxt_description
    gf_isom_new_stxt_description(iso_file, trackNumber, 'stxt', "text/plain", "UTF-8", (const char *)Data, &outDescriptionIndex);

    // Fuzzing gf_isom_avs3v_config_new
    gf_isom_avs3v_config_new(iso_file, trackNumber, avs3v_config, NULL, NULL, &outDescriptionIndex);

    // Fuzzing gf_isom_get_xml_metadata_description
    const char *xmlnamespace, *schema_loc, *content_encoding;
    gf_isom_get_xml_metadata_description(iso_file, trackNumber, outDescriptionIndex, &xmlnamespace, &schema_loc, &content_encoding);

    free(avs3v_config);
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

        LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    