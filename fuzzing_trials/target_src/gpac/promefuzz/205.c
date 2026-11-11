// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_stxt_get_description at sample_descs.c:1385:8 in isomedia.h
// gf_isom_set_media_language at isom_write.c:297:8 in isomedia.h
// gf_isom_new_webvtt_description at sample_descs.c:1637:8 in isomedia.h
// gf_isom_set_generic_protection at drm_sample.c:626:8 in isomedia.h
// gf_isom_av1_config_new at avc_ext.c:2007:8 in isomedia.h
// gf_isom_change_ismacryp_protection at drm_sample.c:386:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Attempt to open a dummy ISO file with a temporary directory as NULL
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
}

static GF_AV1Config* create_dummy_av1_config() {
    GF_AV1Config* cfg = (GF_AV1Config*)malloc(sizeof(GF_AV1Config));
    if (cfg) {
        memset(cfg, 0, sizeof(GF_AV1Config));
    }
    return cfg;
}

int LLVMFuzzerTestOneInput_205(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    
    GF_ISOFile* isofile = create_dummy_isofile();
    if (!isofile) return 0;

    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = (Size > 1) ? Data[1] : 0;
    u32 scheme_type = (Size > 2) ? Data[2] : 0;
    u32 scheme_version = (Size > 3) ? Data[3] : 0;
    const char* dummy_uri = "dummy_uri";
    const char* dummy_language = "eng";
    const char* mime = NULL;
    const char* encoding = NULL;
    const char* config = NULL;
    u32 outDescriptionIndex = 0;

    gf_isom_stxt_get_description(isofile, trackNumber, sampleDescriptionIndex, &mime, &encoding, &config);
    gf_isom_set_media_language(isofile, trackNumber, (char*)dummy_language);
    gf_isom_new_webvtt_description(isofile, trackNumber, dummy_uri, dummy_uri, &outDescriptionIndex, dummy_uri);
    gf_isom_set_generic_protection(isofile, trackNumber, sampleDescriptionIndex, scheme_type, scheme_version, (char*)dummy_uri, (char*)dummy_uri);

    GF_AV1Config* av1_cfg = create_dummy_av1_config();
    if (av1_cfg) {
        gf_isom_av1_config_new(isofile, trackNumber, av1_cfg, dummy_uri, dummy_uri, &outDescriptionIndex);
        free(av1_cfg);
    }

    gf_isom_change_ismacryp_protection(isofile, trackNumber, sampleDescriptionIndex, (char*)dummy_uri, (char*)dummy_uri);

    gf_isom_close(isofile);
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

        LLVMFuzzerTestOneInput_205(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    