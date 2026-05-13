// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>

static void setup_codec_context(aom_codec_ctx_t &codec_ctx, aom_codec_iface_t *iface) {
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec: %s\n", aom_codec_err_to_string(res));
    }
}

static void teardown_codec_context(aom_codec_ctx_t &codec_ctx) {
    aom_codec_err_t res = aom_codec_destroy(&codec_ctx);
    if (res != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to destroy codec: %s\n", aom_codec_err_to_string(res));
    }
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) return 0;

    setup_codec_context(codec_ctx, iface);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_GF_MAX_PYRAMID_HEIGHT
    int gf_max_pyramid_height = Data[0] % 5; // Assuming max value is 4
    aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, gf_max_pyramid_height);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER
    int enable_intra_edge_filter = Data[0] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, enable_intra_edge_filter);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MAX_INTER_BITRATE_PCT
    int max_inter_bitrate_pct = Data[0] % 100 + 1; // 1 to 100
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_INTER_BITRATE_PCT, max_inter_bitrate_pct);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_CHROMA_SUBSAMPLING_X
    int chroma_subsampling_x = Data[0] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_CHROMA_SUBSAMPLING_X, chroma_subsampling_x);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_U
    int qm_u = Data[0] % 16; // Assuming range 0 to 15
    aom_codec_control(&codec_ctx, AV1E_SET_QM_U, qm_u);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_LOW_COMPLEXITY_DECODE
    int enable_low_complexity_decode = Data[0] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_LOW_COMPLEXITY_DECODE, enable_low_complexity_decode);

    teardown_codec_context(codec_ctx);

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

        LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    