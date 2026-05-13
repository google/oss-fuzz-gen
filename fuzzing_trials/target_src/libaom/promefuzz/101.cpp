// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS at aomcx.h:2372:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH at aomcx.h:2336:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_RATE_DISTRIBUTION_INFO at aomcx.h:2387:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT at aomcx.h:2258:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH at aomcx.h:2300:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX at aomcx.h:2138:1 in aomcx.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;  // Ensure there's at least some data

    // Initialize codec context
    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    // Assume we have a valid interface for AV1 encoder
    aom_codec_iface_t *iface = aom_codec_av1_cx();

    // Initialize codec
    if (aom_codec_enc_init(&codec, iface, nullptr, 0) != AOM_CODEC_OK) {
        return 0;  // Initialization failed
    }

    // Fuzz the function: aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points = 0;
    aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS(&codec, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);

    // Fuzz the function: aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH
    int enable_tx_size_search = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH(&codec, AV1E_SET_ENABLE_TX_SIZE_SEARCH, enable_tx_size_search);

    // Fuzz the function: aom_codec_control_typechecked_AV1E_SET_RATE_DISTRIBUTION_INFO
    const char *rate_distribution_info = reinterpret_cast<const char*>(Data);
    aom_codec_control_typechecked_AV1E_SET_RATE_DISTRIBUTION_INFO(&codec, AV1E_SET_RATE_DISTRIBUTION_INFO, rate_distribution_info);

    // Fuzz the function: aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT
    int quant_b_adapt = Data[0] % 256;
    aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT(&codec, AV1E_SET_QUANT_B_ADAPT, quant_b_adapt);

    // Fuzz the function: aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH
    const char *vmaf_model_path = "./dummy_file";
    FILE *file = fopen(vmaf_model_path, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH(&codec, AV1E_SET_VMAF_MODEL_PATH, vmaf_model_path);
    }

    // Fuzz the function: aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX
    int enable_rect_tx = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX(&codec, AV1E_SET_ENABLE_RECT_TX, enable_rect_tx);

    // Destroy codec to clean up
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

        LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    