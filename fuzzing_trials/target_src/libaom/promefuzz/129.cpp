// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE at aomcx.h:2213:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_U at aomcx.h:2099:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE at aomcx.h:2237:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_MAX at aomcx.h:2093:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS at aomcx.h:2421:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP at aomcx.h:2378:1 in aomcx.h
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
#include "aomcx.h"
#include "aom_decoder.h"
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t)) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    aom_codec_err_t res;

    // Initialize codec context with dummy data
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.name = "dummy_codec";
    codec_ctx.iface = nullptr;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.config.enc = nullptr;
    codec_ctx.priv = nullptr;

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE
    if (Size >= sizeof(int)) {
        int deltaq_mode = static_cast<int>(Data[0]);
        res = aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE(&codec_ctx, AV1E_SET_DELTAQ_MODE, deltaq_mode);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_U
    if (Size >= 2 * sizeof(int)) {
        int qm_u = static_cast<int>(Data[1]);
        res = aom_codec_control_typechecked_AV1E_SET_QM_U(&codec_ctx, AV1E_SET_QM_U, qm_u);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE
    if (Size >= 3 * sizeof(int)) {
        int denoise_block_size = static_cast<int>(Data[2]);
        res = aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(&codec_ctx, AV1E_SET_DENOISE_BLOCK_SIZE, denoise_block_size);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_MAX
    if (Size >= 4 * sizeof(int)) {
        int qm_max = static_cast<int>(Data[3]);
        res = aom_codec_control_typechecked_AV1E_SET_QM_MAX(&codec_ctx, AV1E_SET_QM_MAX, qm_max);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS
    if (Size >= 5 * sizeof(int)) {
        int enable_adaptive_sharpness = static_cast<int>(Data[4]);
        res = aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS(&codec_ctx, AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS, enable_adaptive_sharpness);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP
    if (Size >= 6 * sizeof(int)) {
        int enable_sb_qp_sweep = static_cast<int>(Data[5]);
        res = aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP(&codec_ctx, AV1E_ENABLE_SB_QP_SWEEP, enable_sb_qp_sweep);
    }

    // Clean up any resources if necessary
    // Since the codec context is not fully initialized, there's no need to destroy it

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

        LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    