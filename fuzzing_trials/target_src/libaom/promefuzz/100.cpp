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
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aomdx.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>

static aom_codec_ctx_t* initialize_codec_context() {
    aom_codec_ctx_t *codec_ctx = new aom_codec_ctx_t();
    codec_ctx->name = "AV1 Codec";
    codec_ctx->iface = aom_codec_av1_cx();
    codec_ctx->err = AOM_CODEC_OK;
    codec_ctx->init_flags = 0;
    codec_ctx->config.enc = nullptr;
    codec_ctx->priv = nullptr;
    return codec_ctx;
}

static void cleanup_codec_context(aom_codec_ctx_t *codec_ctx) {
    if (codec_ctx) {
        aom_codec_destroy(codec_ctx);
        delete codec_ctx;
    }
}

extern "C" int LLVMFuzzerTestOneInput_100(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t *codec_ctx = initialize_codec_context();
    if (!codec_ctx) return 0;

    // Fuzz aom_codec_control_typechecked_AV1E_ENABLE_EXT_TILE_DEBUG
    int enable_debug = Data[0] % 2;
    aom_codec_control(codec_ctx, AV1E_ENABLE_EXT_TILE_DEBUG, enable_debug);

    // Fuzz aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT
    if (Size >= 3) {
        int frame_size_limit = (Data[1] << 8) | Data[2];
        aom_codec_control(codec_ctx, AOMD_SET_FRAME_SIZE_LIMIT, frame_size_limit);
    }

    // Fuzz aom_codec_control_typechecked_AOMD_GET_ORDER_HINT
    unsigned int order_hint;
    aom_codec_control(codec_ctx, AOMD_GET_ORDER_HINT, &order_hint);

    // Fuzz aom_codec_control_typechecked_AOME_SET_NUMBER_SPATIAL_LAYERS
    if (Size >= 4) {
        int num_spatial_layers = Data[3] % 10; // Assuming a max of 10 spatial layers
        aom_codec_control(codec_ctx, AOME_SET_NUMBER_SPATIAL_LAYERS, num_spatial_layers);
    }

    // Fuzz aom_codec_control_typechecked_AOME_SET_TUNING
    if (Size >= 5) {
        int tuning = Data[4] % 3; // Assuming 3 tuning modes
        aom_codec_control(codec_ctx, AOME_SET_TUNING, tuning);
    }

    // Fuzz aom_codec_control_typechecked_AOME_GET_LOOPFILTER_LEVEL
    int loopfilter_level;
    aom_codec_control(codec_ctx, AOME_GET_LOOPFILTER_LEVEL, &loopfilter_level);

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

        LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    