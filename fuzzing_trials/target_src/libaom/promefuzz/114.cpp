// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
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
#include "aomdx.h"
#include "aom.h"
#include "aom_codec.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aomcx.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_encoder.h"

static void initialize_codec_context(aom_codec_ctx_t &ctx) {
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    aom_codec_err_t res = aom_codec_enc_config_default(iface, &cfg, 0);
    if (res == AOM_CODEC_OK) {
        res = aom_codec_enc_init(&ctx, iface, &cfg, 0);
    }
    if (res != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec context\n");
        std::abort();
    }
}

static void cleanup_codec_context(aom_codec_ctx_t &ctx) {
    aom_codec_err_t res = aom_codec_destroy(&ctx);
    if (res != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to destroy codec context\n");
    }
}

extern "C" int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size) {
    if (Size < 3) return 0; // Ensure we have enough data for our operations

    aom_codec_ctx_t codec_ctx;
    initialize_codec_context(codec_ctx);

    // Fuzz aom_codec_control_typechecked_AOMD_GET_SHOW_FRAME_FLAG
    int show_frame_flag;
    aom_codec_control(&codec_ctx, AOMD_GET_SHOW_FRAME_FLAG, &show_frame_flag);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_WEDGE
    int enable_interintra_wedge = Data[0] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_interintra_wedge);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_WARPED_MOTION
    int enable_warped_motion = Data[1] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_WARPED_MOTION, enable_warped_motion);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_GOP_INFO
    aom_gop_info_t gop_info;
    aom_codec_control(&codec_ctx, AV1E_GET_GOP_INFO, &gop_info);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE
    int screen_content_mode = Data[2] % 2; // 0 or 1
    aom_codec_control(&codec_ctx, AV1E_SET_SCREEN_CONTENT_DETECTION_MODE, screen_content_mode);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_BASELINE_GF_INTERVAL
    int baseline_gf_interval;
    aom_codec_control(&codec_ctx, AV1E_GET_BASELINE_GF_INTERVAL, &baseline_gf_interval);

    cleanup_codec_context(codec_ctx);
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

        LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    