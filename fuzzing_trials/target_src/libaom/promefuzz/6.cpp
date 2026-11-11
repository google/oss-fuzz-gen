// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
}

static void fuzz_aom_codec_control(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + 1) return;

    int control_id = *reinterpret_cast<const int*>(Data);
    int control_value = static_cast<int>(Data[sizeof(int)]);

    switch (control_id) {
        case 1:
            aom_codec_control(codec, AV1E_ENABLE_SB_MULTIPASS_UNIT_TEST, control_value);
            break;
        case 2:
            aom_codec_control(codec, AV1E_SET_FP_MT_UNIT_TEST, control_value);
            break;
        case 3:
            aom_codec_control(codec, AV1E_SET_DV_COST_UPD_FREQ, control_value);
            break;
        case 4:
            aom_codec_control(codec, AOME_SET_MAX_INTRA_BITRATE_PCT, control_value);
            break;
        case 5:
            aom_codec_control(codec, AV1E_ENABLE_RATE_GUIDE_DELTAQ, control_value);
            break;
        case 6:
            aom_codec_control(codec, AV1E_SET_BITRATE_ONE_PASS_CBR, control_value);
            break;
        default:
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;

    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    if (aom_codec_enc_init(&codec, iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    fuzz_aom_codec_control(&codec, Data, Size);

    aom_codec_destroy(&codec);
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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    