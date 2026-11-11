// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_audio_info at isom_read.c:3880:8 in isomedia.h
// gf_isom_set_track_interleaving_group at isom_write.c:5868:8 in isomedia.h
// gf_isom_rtp_set_timescale at hint_track.c:226:8 in isomedia.h
// gf_isom_remove_stream_description at isom_write.c:909:8 in isomedia.h
// gf_isom_get_visual_info at isom_read.c:3821:8 in isomedia.h
// gf_isom_set_ctts_v1 at isom_write.c:7867:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void fuzz_gf_isom_get_audio_info(GF_ISOFile *isom_file) {
    u32 SampleRate, Channels, bitsPerSample;
    gf_isom_get_audio_info(isom_file, 1, 1, &SampleRate, &Channels, &bitsPerSample);
}

static void fuzz_gf_isom_set_track_interleaving_group(GF_ISOFile *isom_file) {
    gf_isom_set_track_interleaving_group(isom_file, 1, 1);
}

static void fuzz_gf_isom_rtp_set_timescale(GF_ISOFile *isom_file) {
    gf_isom_rtp_set_timescale(isom_file, 1, 1, 90000);
}

static void fuzz_gf_isom_remove_stream_description(GF_ISOFile *isom_file) {
    gf_isom_remove_stream_description(isom_file, 1, 1);
}

static void fuzz_gf_isom_get_visual_info(GF_ISOFile *isom_file) {
    u32 Width, Height;
    gf_isom_get_visual_info(isom_file, 1, 1, &Width, &Height);
}

static void fuzz_gf_isom_set_ctts_v1(GF_ISOFile *isom_file) {
    gf_isom_set_ctts_v1(isom_file, 1, 0);
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    fuzz_gf_isom_get_audio_info(isom_file);
    fuzz_gf_isom_set_track_interleaving_group(isom_file);
    fuzz_gf_isom_rtp_set_timescale(isom_file);
    fuzz_gf_isom_remove_stream_description(isom_file);
    fuzz_gf_isom_get_visual_info(isom_file);
    fuzz_gf_isom_set_ctts_v1(isom_file);

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    