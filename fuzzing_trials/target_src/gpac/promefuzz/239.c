// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_rtp_packet_set_flags at hint_track.c:579:8 in isomedia.h
// gf_isom_probe_data at isom_read.c:195:5 in isomedia.h
// gf_isom_set_sample_padding at isom_read.c:2492:8 in isomedia.h
// gf_isom_get_user_data at isom_read.c:2769:8 in isomedia.h
// gf_isom_cenc_get_sample_aux_info at drm_sample.c:1645:8 in isomedia.h
// gf_isom_remove_user_data at isom_write.c:3758:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void fuzz_gf_isom_rtp_packet_set_flags(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 6) return; // Ensure there's enough data for trackNumber and flags
    u32 trackNumber = Data[0];
    u8 PackingBit = Data[1] & 1;
    u8 eXtensionBit = Data[2] & 1;
    u8 MarkerBit = Data[3] & 1;
    u8 disposable_packet = Data[4] & 1;
    u8 IsRepeatedPacket = Data[5] & 1;

    gf_isom_rtp_packet_set_flags(isom_file, trackNumber, PackingBit, eXtensionBit, MarkerBit, disposable_packet, IsRepeatedPacket);
}

static void fuzz_gf_isom_probe_data(const uint8_t *Data, size_t Size) {
    gf_isom_probe_data(Data, (u32)Size);
}

static void fuzz_gf_isom_set_sample_padding(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 5) return; // Ensure there's enough data for trackNumber and padding_bytes
    u32 trackNumber = Data[0];
    u32 padding_bytes = *(u32 *)(Data + 1);

    gf_isom_set_sample_padding(isom_file, trackNumber, padding_bytes);
}

static void fuzz_gf_isom_get_user_data(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 37) return; // Ensure there's enough data for parameters
    u32 trackNumber = Data[0];
    u32 UserDataType = *(u32 *)(Data + 1);
    bin128 UUID;
    memcpy(UUID, Data + 5, sizeof(bin128));
    u32 UserDataIndex = *(u32 *)(Data + 21);
    u8 *userData = NULL;
    u32 userDataSize = 0;

    gf_isom_get_user_data(isom_file, trackNumber, UserDataType, UUID, UserDataIndex, &userData, &userDataSize);
    free(userData);
}

static void fuzz_gf_isom_cenc_get_sample_aux_info(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 13) return; // Ensure there's enough data for parameters
    u32 trackNumber = Data[0];
    u32 sampleNumber = *(u32 *)(Data + 1);
    u32 sampleDescIndex = *(u32 *)(Data + 5);
    u32 container_type = *(u32 *)(Data + 9);
    u8 *out_buffer = NULL;
    u32 outSize = 0;

    gf_isom_cenc_get_sample_aux_info(isom_file, trackNumber, sampleNumber, sampleDescIndex, &container_type, &out_buffer, &outSize);
    free(out_buffer);
}

static void fuzz_gf_isom_remove_user_data(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 21) return; // Ensure there's enough data for parameters
    u32 trackNumber = Data[0];
    u32 UserDataType = *(u32 *)(Data + 1);
    bin128 UUID;
    memcpy(UUID, Data + 5, sizeof(bin128));

    gf_isom_remove_user_data(isom_file, trackNumber, UserDataType, UUID);
}

int LLVMFuzzerTestOneInput_239(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    fuzz_gf_isom_rtp_packet_set_flags(isom_file, Data, Size);
    fuzz_gf_isom_probe_data(Data, Size);
    fuzz_gf_isom_set_sample_padding(isom_file, Data, Size);
    fuzz_gf_isom_get_user_data(isom_file, Data, Size);
    fuzz_gf_isom_cenc_get_sample_aux_info(isom_file, Data, Size);
    fuzz_gf_isom_remove_user_data(isom_file, Data, Size);

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

        LLVMFuzzerTestOneInput_239(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    