// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
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
#include <cstdint>
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

static void handle_error(aom_codec_ctx_t *ctx, const char *msg) {
    if (ctx->err) {
        std::cerr << msg << ": " << aom_codec_err_to_string(ctx->err) << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        handle_error(&codec_ctx, "Failed to initialize codec");
        return 0;
    }

    int control_id = Data[0] % 6;
    int value = Data[1];

    switch (control_id) {
        case 0:
            res = aom_codec_control(&codec_ctx, AOMD_GET_SHOW_FRAME_FLAG, &value);
            handle_error(&codec_ctx, "GET_SHOW_FRAME_FLAG");
            break;
        case 1:
            res = aom_codec_control(&codec_ctx, AOME_SET_NUMBER_SPATIAL_LAYERS, value);
            handle_error(&codec_ctx, "SET_NUMBER_SPATIAL_LAYERS");
            break;
        case 2:
            res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_COMP, value);
            handle_error(&codec_ctx, "SET_ENABLE_INTERINTRA_COMP");
            break;
        case 3:
            res = aom_codec_control(&codec_ctx, AOMD_GET_BASE_Q_IDX, &value);
            handle_error(&codec_ctx, "GET_BASE_Q_IDX");
            break;
        case 4:
            res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_1TO4_PARTITIONS, value);
            handle_error(&codec_ctx, "SET_ENABLE_1TO4_PARTITIONS");
            break;
        case 5:
            res = aom_codec_control(&codec_ctx, AOME_GET_LOOPFILTER_LEVEL, &value);
            handle_error(&codec_ctx, "GET_LOOPFILTER_LEVEL");
            break;
        default:
            break;
    }

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

        LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    