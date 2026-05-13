// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_enable_compression at isom_write.c:2660:8 in isomedia.h
// gf_isom_get_audio_info at isom_read.c:3880:8 in isomedia.h
// gf_isom_ac3_config_update at sample_descs.c:746:8 in isomedia.h
// gf_isom_ac3_config_get at sample_descs.c:342:15 in isomedia.h
// gf_isom_ac3_config_new at sample_descs.c:701:8 in isomedia.h
// gf_isom_set_sample_flags at isom_write.c:8052:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // We assume there is a function in the library to create an ISO file.
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void destroy_dummy_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_202(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 5) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32*)(Data);
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32));
    u32 compress_mode = *(u32*)(Data + 2 * sizeof(u32));
    u32 compress_flags = *(u32*)(Data + 3 * sizeof(u32));
    u32 sampleNumber = *(u32*)(Data + 4 * sizeof(u32));

    // Test gf_isom_enable_compression
    gf_isom_enable_compression(isom_file, compress_mode, compress_flags);

    // Test gf_isom_get_audio_info
    u32 SampleRate, Channels, bitsPerSample;
    gf_isom_get_audio_info(isom_file, trackNumber, sampleDescriptionIndex, &SampleRate, &Channels, &bitsPerSample);

    // Test gf_isom_ac3_config_update
    GF_AC3Config ac3_config;
    memset(&ac3_config, 0, sizeof(GF_AC3Config));
    gf_isom_ac3_config_update(isom_file, trackNumber, sampleDescriptionIndex, &ac3_config);

    // Test gf_isom_ac3_config_get
    GF_AC3Config *ac3_config_get = gf_isom_ac3_config_get(isom_file, trackNumber, sampleDescriptionIndex);
    if (ac3_config_get) {
        free(ac3_config_get);
    }

    // Test gf_isom_ac3_config_new
    u32 outDescriptionIndex;
    gf_isom_ac3_config_new(isom_file, trackNumber, &ac3_config, NULL, NULL, &outDescriptionIndex);

    // Test gf_isom_set_sample_flags
    gf_isom_set_sample_flags(isom_file, trackNumber, sampleNumber, 1, 1, 1, 1);

    destroy_dummy_iso_file(isom_file);

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

        LLVMFuzzerTestOneInput_202(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    