// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_decoder.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int enable_feature = static_cast<int>(Data[0] % 2); // Randomly enable or disable

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec, iface, nullptr, 0);

    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz the AV1E_SET_ENABLE_CFL_INTRA feature
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_CFL_INTRA, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the AV1E_SET_ENABLE_INTRA_EDGE_FILTER feature
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the AV1E_SET_ENABLE_TX_SIZE_SEARCH feature
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_TX_SIZE_SEARCH, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the AV1E_SET_INTRA_DCT_ONLY feature
    res = aom_codec_control(&codec, AV1E_SET_INTRA_DCT_ONLY, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the AV1E_SET_ENABLE_FLIP_IDTX feature
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_FLIP_IDTX, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the AV1E_SET_QUANT_B_ADAPT feature
    res = aom_codec_control(&codec, AV1E_SET_QUANT_B_ADAPT, enable_feature);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec);
        return 0;
    }

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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    