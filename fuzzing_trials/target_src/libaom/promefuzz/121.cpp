// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS at aomcx.h:2372:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_MODE_COST_UPD_FREQ at aomcx.h:2273:1 in aomcx.h
// aom_codec_control_typechecked_AOMD_GET_ORDER_HINT at aomdx.h:604:1 in aomdx.h
// aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX at aomcx.h:2369:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS at aomcx.h:2117:1 in aomcx.h
// aom_codec_control_typechecked_AOME_GET_LOOPFILTER_LEVEL at aomcx.h:2351:1 in aomcx.h
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
}

#include <cstdint>
#include <cstdio>

static void initialize_codec_context(aom_codec_ctx_t &codec_ctx) {
    codec_ctx.name = "dummy_codec";
    codec_ctx.iface = nullptr;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.config.raw = nullptr;
    codec_ctx.priv = nullptr;
}

static void cleanup_codec_context(aom_codec_ctx_t &codec_ctx) {
    // Assuming aom_codec_destroy() is available for cleanup
    aom_codec_destroy(&codec_ctx);
}

extern "C" int LLVMFuzzerTestOneInput_121(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0; // Ensure there is enough data

    aom_codec_ctx_t codec_ctx;
    initialize_codec_context(codec_ctx);

    int control_value = *reinterpret_cast<const int*>(Data);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points = 0;
    aom_codec_err_t res = aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS(
        &codec_ctx, 0, &num_operating_points);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MODE_COST_UPD_FREQ
    res = aom_codec_control_typechecked_AV1E_SET_MODE_COST_UPD_FREQ(
        &codec_ctx, 0, static_cast<unsigned int>(control_value));
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_control_typechecked_AOMD_GET_ORDER_HINT
    unsigned int order_hint = 0;
    res = aom_codec_control_typechecked_AOMD_GET_ORDER_HINT(
        &codec_ctx, 0, &order_hint);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX
    int target_seq_level_idx = 0;
    res = aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX(
        &codec_ctx, 0, &target_seq_level_idx);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS(
        &codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_control_typechecked_AOME_GET_LOOPFILTER_LEVEL
    int loopfilter_level = 0;
    res = aom_codec_control_typechecked_AOME_GET_LOOPFILTER_LEVEL(
        &codec_ctx, 0, &loopfilter_level);
    if (res != AOM_CODEC_OK) {
        // Handle error
    }

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

        LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    