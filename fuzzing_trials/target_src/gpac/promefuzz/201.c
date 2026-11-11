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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_201(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + 1) return 0;

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    const char *mime = NULL;
    const char *encoding = NULL;
    const char *config = NULL;
    char language_code[4] = {0};
    memcpy(language_code, Data + sizeof(u32) * 2, 3);

    GF_Err err = gf_isom_stxt_get_description(isom_file, trackNumber, sampleDescriptionIndex, &mime, &encoding, &config);
    if (err != GF_OK) goto cleanup;

    err = gf_isom_set_media_language(isom_file, trackNumber, language_code);
    if (err != GF_OK) goto cleanup;

    u32 outDescriptionIndex = 0;
    err = gf_isom_new_webvtt_description(isom_file, trackNumber, NULL, NULL, &outDescriptionIndex, config);
    if (err != GF_OK) goto cleanup;

    err = gf_isom_set_generic_protection(isom_file, trackNumber, sampleDescriptionIndex, 0x69614543, 1, NULL, NULL);
    if (err != GF_OK) goto cleanup;

    GF_AV1Config av1Config;
    memset(&av1Config, 0, sizeof(GF_AV1Config));
    err = gf_isom_av1_config_new(isom_file, trackNumber, &av1Config, NULL, NULL, &outDescriptionIndex);
    if (err != GF_OK) goto cleanup;

    err = gf_isom_change_ismacryp_protection(isom_file, trackNumber, sampleDescriptionIndex, NULL, NULL);
    if (err != GF_OK) goto cleanup;

cleanup:
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

        LLVMFuzzerTestOneInput_201(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    