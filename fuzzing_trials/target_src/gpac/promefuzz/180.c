// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_audio_info at isom_read.c:3880:8 in isomedia.h
// gf_isom_get_bitrate at isom_read.c:5967:8 in isomedia.h
// gf_isom_get_dims_description at sample_descs.c:931:8 in isomedia.h
// gf_isom_get_cenc_info at drm_sample.c:726:8 in isomedia.h
// gf_isom_remove_stream_description at isom_write.c:909:8 in isomedia.h
// gf_isom_mvc_config_del at avc_ext.c:1823:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
}

static void destroy_dummy_iso_file(GF_ISOFile* iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_180(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) {
        return 0;
    }

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32));
    Data += sizeof(u32) * 2;
    Size -= sizeof(u32) * 2;

    u32 SampleRate = 0, Channels = 0, bitsPerSample = 0;
    gf_isom_get_audio_info(iso_file, trackNumber, sampleDescriptionIndex, &SampleRate, &Channels, &bitsPerSample);

    u32 average_bitrate = 0, max_bitrate = 0, decode_buffer_size = 0;
    gf_isom_get_bitrate(iso_file, trackNumber, sampleDescriptionIndex, &average_bitrate, &max_bitrate, &decode_buffer_size);

    GF_DIMSDescription desc;
    memset(&desc, 0, sizeof(GF_DIMSDescription));
    gf_isom_get_dims_description(iso_file, trackNumber, sampleDescriptionIndex, &desc);

    u32 outOriginalFormat = 0, outSchemeType = 0, outSchemeVersion = 0;
    gf_isom_get_cenc_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion);

    gf_isom_remove_stream_description(iso_file, trackNumber, sampleDescriptionIndex);

    gf_isom_mvc_config_del(iso_file, trackNumber, sampleDescriptionIndex);

    destroy_dummy_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_180(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    