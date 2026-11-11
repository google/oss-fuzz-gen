// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_enable_compression at isom_write.c:2660:8 in isomedia.h
// gf_isom_get_audio_info at isom_read.c:3880:8 in isomedia.h
// gf_isom_rtp_set_time_sequence_offset at hint_track.c:292:8 in isomedia.h
// gf_isom_opus_config_get_desc at sample_descs.c:557:8 in isomedia.h
// gf_isom_get_visual_info at isom_read.c:3821:8 in isomedia.h
// gf_isom_get_reference_ID at isom_read.c:1270:8 in isomedia.h
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

static void fuzz_gf_isom_enable_compression(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(GF_ISOCompressMode) + sizeof(u32)) return;

    GF_ISOCompressMode compress_mode = *(GF_ISOCompressMode *)Data;
    u32 compress_flags = *(u32 *)(Data + sizeof(GF_ISOCompressMode));

    gf_isom_enable_compression(isom_file, compress_mode, compress_flags);
}

static void fuzz_gf_isom_get_audio_info(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2) return;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 SampleRate, Channels, bitsPerSample;

    gf_isom_get_audio_info(isom_file, trackNumber, sampleDescriptionIndex, &SampleRate, &Channels, &bitsPerSample);
}

static void fuzz_gf_isom_rtp_set_time_sequence_offset(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return;

    u32 trackNumber = *(u32 *)Data;
    u32 HintDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 SequenceNumberOffset = *(u32 *)(Data + 2 * sizeof(u32));

    gf_isom_rtp_set_time_sequence_offset(isom_file, trackNumber, HintDescriptionIndex, SequenceNumberOffset);
}

static void fuzz_gf_isom_opus_config_get_desc(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + sizeof(GF_OpusConfig)) return;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    GF_OpusConfig opcfg;

    gf_isom_opus_config_get_desc(isom_file, trackNumber, sampleDescriptionIndex, &opcfg);
}

static void fuzz_gf_isom_get_visual_info(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2) return;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 Width, Height;

    gf_isom_get_visual_info(isom_file, trackNumber, sampleDescriptionIndex, &Width, &Height);
}

static void fuzz_gf_isom_get_reference_ID(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return;

    u32 trackNumber = *(u32 *)Data;
    u32 referenceType = *(u32 *)(Data + sizeof(u32));
    u32 referenceIndex = *(u32 *)(Data + 2 * sizeof(u32));
    GF_ISOTrackID refTrackID;

    gf_isom_get_reference_ID(isom_file, trackNumber, referenceType, referenceIndex, &refTrackID);
}

int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size) {
    // Allocate memory for GF_ISOFile as a dummy placeholder
    size_t isom_file_size = 1024; // Arbitrary size for the example
    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(isom_file_size);
    if (!isom_file) return 0;

    memset(isom_file, 0, isom_file_size);

    fuzz_gf_isom_enable_compression(isom_file, Data, Size);
    fuzz_gf_isom_get_audio_info(isom_file, Data, Size);
    fuzz_gf_isom_rtp_set_time_sequence_offset(isom_file, Data, Size);
    fuzz_gf_isom_opus_config_get_desc(isom_file, Data, Size);
    fuzz_gf_isom_get_visual_info(isom_file, Data, Size);
    fuzz_gf_isom_get_reference_ID(isom_file, Data, Size);

    free(isom_file);
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

        LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    