// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
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
#include <iostream>
#include <fstream>
#include <cstdint>
#include <aom/aomdx.h>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>

static void initialize_codec(aom_codec_ctx_t &ctx, aom_codec_iface_t *iface) {
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        std::cerr << "Failed to get default codec config." << std::endl;
        return;
    }
    if (aom_codec_enc_init(&ctx, iface, &cfg, 0) != AOM_CODEC_OK) {
        std::cerr << "Failed to initialize codec." << std::endl;
        return;
    }
}

static void cleanup_codec(aom_codec_ctx_t &ctx) {
    if (aom_codec_destroy(&ctx) != AOM_CODEC_OK) {
        std::cerr << "Failed to destroy codec." << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();

    initialize_codec(codec_ctx, iface);

    // Fuzz aom_codec_control_typechecked_AOMD_GET_SHOW_FRAME_FLAG
    int show_frame_flag;
    aom_codec_control(&codec_ctx, AOMD_GET_SHOW_FRAME_FLAG, &show_frame_flag);

    // Fuzz aom_codec_control_typechecked_AOME_SET_NUMBER_SPATIAL_LAYERS
    int num_spatial_layers = Data[0] % 4; // Limit to 4 layers for fuzzing
    aom_codec_control(&codec_ctx, AOME_SET_NUMBER_SPATIAL_LAYERS, &num_spatial_layers);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS
    int quantizer_value = Data[0] % 256;
    aom_codec_control(&codec_ctx, AV1E_SET_QUANTIZER_ONE_PASS, &quantizer_value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE
    int timing_info_type = Data[0] % 3; // Assuming 3 timing info types
    aom_codec_control(&codec_ctx, AV1E_SET_TIMING_INFO_TYPE, &timing_info_type);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH
    int enable_tx_size_search = Data[0] % 2; // Enable or disable
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_TX_SIZE_SEARCH, &enable_tx_size_search);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY
    int intra_default_tx_only = Data[0] % 2; // Enable or disable
    aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, &intra_default_tx_only);

    cleanup_codec(codec_ctx);

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

        LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    