// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS at aomcx.h:2372:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY at aomcx.h:2255:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE at aomcx.h:2225:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_BASELINE_GF_INTERVAL at aomcx.h:2315:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX at aomcx.h:2138:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY at aomcx.h:2252:1 in aomcx.h
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

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Prepare a dummy file if needed
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) {
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Initialize codec context
    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    // Initialize codec interface
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) {
        return 0;
    }

    // Initialize codec with default encoder configuration
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Initialize codec
    if (aom_codec_enc_init(&codec, iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz different API functions
    int control_value = *reinterpret_cast<const int*>(Data);
    aom_codec_err_t res;

    // Test aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points;
    res = aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS(&codec, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Test aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY
    res = aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(&codec, AV1E_SET_INTRA_DEFAULT_TX_ONLY, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Test aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE
    res = aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE(&codec, AV1E_SET_TIMING_INFO_TYPE, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Test aom_codec_control_typechecked_AV1E_GET_BASELINE_GF_INTERVAL
    int baseline_gf_interval;
    res = aom_codec_control_typechecked_AV1E_GET_BASELINE_GF_INTERVAL(&codec, AV1E_GET_BASELINE_GF_INTERVAL, &baseline_gf_interval);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Test aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX(&codec, AV1E_SET_ENABLE_RECT_TX, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Test aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY
    res = aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY(&codec, AV1E_SET_INTER_DCT_ONLY, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    