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
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
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
#include <iostream>
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t)) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    codec_ctx.iface = iface;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.priv = nullptr;

    // Initialize codec context
    if (aom_codec_enc_init(&codec_ctx, iface, nullptr, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points;
    aom_codec_control(&codec_ctx, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX
    int target_seq_level_idx;
    aom_codec_control(&codec_ctx, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &target_seq_level_idx);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_RATE_DISTRIBUTION_INFO
    int rate_distribution_info = Data[0];
    aom_codec_control(&codec_ctx, AV1E_SET_RATE_DISTRIBUTION_INFO, &rate_distribution_info);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH
    std::ofstream dummy_file("./dummy_file");
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }
    const char *vmaf_model_path = "./dummy_file";
    aom_codec_control(&codec_ctx, AV1E_SET_VMAF_MODEL_PATH, vmaf_model_path);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX
    int enable_rect_tx = Data[0] % 2;
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, enable_rect_tx);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY
    int inter_dct_only = Data[0] % 2;
    aom_codec_control(&codec_ctx, AV1E_SET_INTER_DCT_ONLY, inter_dct_only);

    // Cleanup
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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    