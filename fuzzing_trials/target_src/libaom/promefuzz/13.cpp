// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <cstdint>
#include <cstring>
#include <aom/aomcx.h>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize codec interface
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) return 0;

    // Initialize codec context
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Extract integer values from the input data
    int param1 = *reinterpret_cast<const int*>(Data);
    int param2 = (Size >= 2 * sizeof(int)) ? *reinterpret_cast<const int*>(Data + sizeof(int)) : 0;
    int param3 = (Size >= 3 * sizeof(int)) ? *reinterpret_cast<const int*>(Data + 2 * sizeof(int)) : 0;
    int param4 = (Size >= 4 * sizeof(int)) ? *reinterpret_cast<const int*>(Data + 3 * sizeof(int)) : 0;
    int param5 = (Size >= 5 * sizeof(int)) ? *reinterpret_cast<const int*>(Data + 4 * sizeof(int)) : 0;
    int param6 = (Size >= 6 * sizeof(int)) ? *reinterpret_cast<const int*>(Data + 5 * sizeof(int)) : 0;

    // Invoke target API functions with extracted parameters
    aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, param1);
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_INTER_BITRATE_PCT, param2);
    aom_codec_control(&codec_ctx, AV1E_SET_QM_MIN, param3);
    aom_codec_control(&codec_ctx, AV1E_SET_FP_MT_UNIT_TEST, param4);
    aom_codec_control(&codec_ctx, AV1E_SET_RTC_EXTERNAL_RC, param5);
    aom_codec_control(&codec_ctx, AV1E_SET_QM_U, param6);

    // Clean up codec context
    aom_codec_destroy(&codec_ctx);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    