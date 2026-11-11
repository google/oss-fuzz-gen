// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE at aomcx.h:2396:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING at aomcx.h:2375:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ at aomcx.h:2324:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF at aomcx.h:2357:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_CQ_LEVEL at aomcx.h:1968:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_AUTO_TILES at aomcx.h:2402:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include "aom/aomdx.h"
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_external_partition.h"
#include "aom/aom_decoder.h"
#include "aom/aomcx.h"
#include "aom/aom_integer.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_image.h"
#include "aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, NULL, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Extract integer parameters from the input data
    int param = *(reinterpret_cast<const int*>(Data));
    Data += sizeof(int);
    Size -= sizeof(int);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE
    aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE(&codec_ctx, AV1E_SET_SVC_FRAME_DROP_MODE, param);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING
    aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING(&codec_ctx, AV1E_SET_SKIP_POSTPROC_FILTERING, param);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
    aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ(&codec_ctx, AV1E_SET_DV_COST_UPD_FREQ, param);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF
    aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF(&codec_ctx, AV1E_SET_AUTO_INTRA_TOOLS_OFF, param);

    // Fuzz aom_codec_control_typechecked_AOME_SET_CQ_LEVEL
    aom_codec_control_typechecked_AOME_SET_CQ_LEVEL(&codec_ctx, AOME_SET_CQ_LEVEL, param);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_AUTO_TILES
    aom_codec_control_typechecked_AV1E_SET_AUTO_TILES(&codec_ctx, AV1E_SET_AUTO_TILES, param);

    // Clean up
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

        LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    