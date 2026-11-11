// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
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
#include <iostream>
#include "aom.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.iface = aom_codec_av1_cx();

    // Initialize aom_codec_enc_cfg_t
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(codec_ctx.iface, &cfg, 0)) {
        return 0;
    }

    // Initialize the codec
    if (aom_codec_enc_init(&codec_ctx, codec_ctx.iface, &cfg, 0)) {
        return 0;
    }

    // Extract an integer value from the input data
    int value = *reinterpret_cast<const int*>(Data);

    // Fuzz different API functions with the integer value
    aom_codec_err_t res;

    res = aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_GF_MAX_PYRAMID_HEIGHT: " << aom_codec_err_to_string(res) << std::endl;
    }

    res = aom_codec_control(&codec_ctx, AV1E_SET_MAX_INTER_BITRATE_PCT, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_MAX_INTER_BITRATE_PCT: " << aom_codec_err_to_string(res) << std::endl;
    }

    res = aom_codec_control(&codec_ctx, AV1E_SET_QM_V, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_QM_V: " << aom_codec_err_to_string(res) << std::endl;
    }

    res = aom_codec_control(&codec_ctx, AV1E_SET_CHROMA_SUBSAMPLING_X, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_CHROMA_SUBSAMPLING_X: " << aom_codec_err_to_string(res) << std::endl;
    }

    res = aom_codec_control(&codec_ctx, AV1E_SET_QM_U, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_QM_U: " << aom_codec_err_to_string(res) << std::endl;
    }

    res = aom_codec_control(&codec_ctx, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP: " << aom_codec_err_to_string(res) << std::endl;
    }

    // Clean up
    if (aom_codec_destroy(&codec_ctx)) {
        std::cerr << "Error destroying codec: " << aom_codec_err_to_string(codec_ctx.err) << std::endl;
    }

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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    