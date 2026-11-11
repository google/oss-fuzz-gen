// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_3gp_config_new at sample_descs.c:567:8 in isomedia.h
// gf_isom_get_pcm_config at sample_descs.c:1972:8 in isomedia.h
// gf_isom_3gp_config_update at sample_descs.c:660:8 in isomedia.h
// gf_isom_new_track at isom_write.c:863:5 in isomedia.h
// gf_isom_get_visual_info at isom_read.c:3821:8 in isomedia.h
// gf_isom_3gp_config_get at sample_descs.c:304:15 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void free_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_270(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = Data[0];
    u32 flags, pcm_size;
    u32 outDescriptionIndex;
    GF_3GPConfig config;

    // Fuzz gf_isom_3gp_config_new
    gf_isom_3gp_config_new(isom_file, trackNumber, &config, NULL, NULL, &outDescriptionIndex);

    // Fuzz gf_isom_get_pcm_config
    gf_isom_get_pcm_config(isom_file, trackNumber, sampleDescriptionIndex, &flags, &pcm_size);

    // Fuzz gf_isom_3gp_config_update
    gf_isom_3gp_config_update(isom_file, trackNumber, &config, sampleDescriptionIndex);

    // Fuzz gf_isom_new_track
    gf_isom_new_track(isom_file, 0, 0, 0);

    // Fuzz gf_isom_get_visual_info
    u32 Width, Height;
    gf_isom_get_visual_info(isom_file, trackNumber, sampleDescriptionIndex, &Width, &Height);

    // Fuzz gf_isom_3gp_config_get
    gf_isom_3gp_config_get(isom_file, trackNumber, sampleDescriptionIndex);

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

        LLVMFuzzerTestOneInput_270(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    