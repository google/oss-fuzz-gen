// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
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
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>

static aom_codec_ctx_t* initialize_codec() {
    aom_codec_ctx_t* codec_ctx = new aom_codec_ctx_t;
    aom_codec_iface_t* iface = aom_codec_av1_cx();
    if (aom_codec_enc_init(codec_ctx, iface, nullptr, 0) != AOM_CODEC_OK) {
        delete codec_ctx;
        return nullptr;
    }
    return codec_ctx;
}

static void cleanup_codec(aom_codec_ctx_t* codec_ctx) {
    if (codec_ctx) {
        aom_codec_destroy(codec_ctx);
        delete codec_ctx;
    }
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    aom_codec_ctx_t* codec_ctx = initialize_codec();
    if (!codec_ctx) {
        return 0;
    }

    int parameter = static_cast<int>(Data[0]);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points = 0;
    aom_codec_control(codec_ctx, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_WARPED_MOTION
    aom_codec_control(codec_ctx, AV1E_SET_ENABLE_WARPED_MOTION, parameter % 2);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE
    aom_codec_control(codec_ctx, AV1E_SET_SCREEN_CONTENT_DETECTION_MODE, parameter % 2);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH
    aom_codec_control(codec_ctx, AV1E_SET_ENABLE_TX_SIZE_SEARCH, parameter % 2);

    // Fuzz aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC
    int high_motion_content = 0;
    aom_codec_control(codec_ctx, AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC, &high_motion_content);

    cleanup_codec(codec_ctx);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    