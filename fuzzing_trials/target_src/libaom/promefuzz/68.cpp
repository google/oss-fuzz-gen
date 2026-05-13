// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
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
extern "C" {
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
}

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

static void initialize_codec_context(aom_codec_ctx_t &codec_ctx) {
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.name = "AV1 Codec Context";
    codec_ctx.iface = aom_codec_av1_cx();
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
}

static void cleanup_codec_context(aom_codec_ctx_t &codec_ctx) {
    if (codec_ctx.iface) {
        aom_codec_destroy(&codec_ctx);
    }
}

extern "C" int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int param = 0;
    memcpy(&param, Data, sizeof(int));

    aom_codec_ctx_t codec_ctx;
    initialize_codec_context(codec_ctx);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_LOOPFILTER_CONTROL
    aom_codec_control(&codec_ctx, AV1E_SET_LOOPFILTER_CONTROL, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY
    aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET
    aom_codec_control(&codec_ctx, AV1E_SET_REDUCED_REFERENCE_SET, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_COMP_PRED
    aom_svc_ref_frame_comp_pred_t svc_pred;
    svc_pred.use_comp_pred[0] = param & 0x1;
    svc_pred.use_comp_pred[1] = (param >> 1) & 0x1;
    svc_pred.use_comp_pred[2] = (param >> 2) & 0x1;
    aom_codec_control(&codec_ctx, AV1E_SET_SVC_REF_FRAME_COMP_PRED, &svc_pred);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_ENABLE_REF_FRAME_MVS
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_REF_FRAME_MVS, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY
    aom_codec_control(&codec_ctx, AV1E_SET_INTER_DCT_ONLY, param);

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

        LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    