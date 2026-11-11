// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE at aomcx.h:2213:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE at aomcx.h:2237:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS at aomcx.h:2421:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_Y at aomcx.h:2096:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DIST_8X8 at aomcx.h:2087:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP at aomcx.h:2378:1 in aomcx.h
#include <iostream>
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

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 6) {
        return 0;
    }

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    int deltaq_mode = reinterpret_cast<const int*>(Data)[0];
    int denoise_block_size = reinterpret_cast<const int*>(Data)[1];
    int enable_adaptive_sharpness = reinterpret_cast<const int*>(Data)[2];
    int qm_y = reinterpret_cast<const int*>(Data)[3];
    int enable_dist_8x8 = reinterpret_cast<const int*>(Data)[4];
    int enable_sb_qp_sweep = reinterpret_cast<const int*>(Data)[5];

    codec.name = "dummy_codec";
    codec.iface = nullptr;
    codec.err = AOM_CODEC_OK;
    codec.init_flags = 0;
    codec.config.raw = nullptr;
    codec.priv = nullptr;

    // Use the correct control function signature with an additional control ID
    aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE(&codec, AV1E_SET_DELTAQ_MODE, deltaq_mode);
    aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(&codec, AV1E_SET_DENOISE_BLOCK_SIZE, denoise_block_size);
    aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS(&codec, AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS, enable_adaptive_sharpness);
    aom_codec_control_typechecked_AV1E_SET_QM_Y(&codec, AV1E_SET_QM_Y, qm_y);
    aom_codec_control_typechecked_AV1E_SET_ENABLE_DIST_8X8(&codec, AV1E_SET_ENABLE_RECT_TX, enable_dist_8x8); // Corrected control ID
    aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP(&codec, AV1E_ENABLE_SB_QP_SWEEP, enable_sb_qp_sweep);

    if (codec.err != AOM_CODEC_OK) {
        fprintf(stderr, "Codec error: %d\n", codec.err);
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

        LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    