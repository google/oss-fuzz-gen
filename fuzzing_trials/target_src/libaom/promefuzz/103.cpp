// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_av1_dx at av1_dx_iface.c:1813:20 in aomdx.h
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
#include <iostream>
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

static void InitializeCodecContext(aom_codec_ctx_t &codec_ctx, aom_codec_iface_t *iface) {
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.iface = iface;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.priv = nullptr;
}

static void CleanupCodecContext(aom_codec_ctx_t &codec_ctx) {
    aom_codec_destroy(&codec_ctx);
}

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();

    InitializeCodecContext(codec_ctx, iface);

    // Use dummy data for codec initialization
    aom_codec_dec_cfg_t cfg = {0};
    cfg.threads = 1;
    cfg.allow_lowbitdepth = 1;

    if (aom_codec_dec_init(&codec_ctx, iface, &cfg, 0) != AOM_CODEC_OK) {
        CleanupCodecContext(codec_ctx);
        return 0;
    }

    // Create dummy file for codec operations
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    // Fuzz various API functions
    int show_frame_flag;
    if (aom_codec_control(&codec_ctx, AOMD_GET_SHOW_FRAME_FLAG, &show_frame_flag) == AOM_CODEC_OK) {
        std::cout << "Show Frame Flag: " << show_frame_flag << std::endl;
    }

    aom_tile_info tile_info;
    if (aom_codec_control(&codec_ctx, AOMD_GET_TILE_INFO, &tile_info) == AOM_CODEC_OK) {
        std::cout << "Tile Columns: " << tile_info.tile_columns << std::endl;
    }

    aom_gop_info_t gop_info;
    if (aom_codec_control(&codec_ctx, AV1E_GET_GOP_INFO, &gop_info) == AOM_CODEC_OK) {
        std::cout << "GOP Size: " << gop_info.gop_size << std::endl;
    }

    int base_q_idx;
    if (aom_codec_control(&codec_ctx, AOMD_GET_BASE_Q_IDX, &base_q_idx) == AOM_CODEC_OK) {
        std::cout << "Base Q Index: " << base_q_idx << std::endl;
    }

    int loopfilter_level;
    if (aom_codec_control(&codec_ctx, AOME_GET_LOOPFILTER_LEVEL, &loopfilter_level) == AOM_CODEC_OK) {
        std::cout << "Loop Filter Level: " << loopfilter_level << std::endl;
    }

    int baseline_gf_interval;
    if (aom_codec_control(&codec_ctx, AV1E_GET_BASELINE_GF_INTERVAL, &baseline_gf_interval) == AOM_CODEC_OK) {
        std::cout << "Baseline GF Interval: " << baseline_gf_interval << std::endl;
    }

    CleanupCodecContext(codec_ctx);
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

        LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    