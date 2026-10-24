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
#include <iostream>
#include <fstream>
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

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Prepare input data
    int input_value = *reinterpret_cast<const int*>(Data);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_GF_MAX_PYRAMID_HEIGHT
    aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, input_value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE
    aom_codec_control(&codec_ctx, AV1E_SET_SVC_FRAME_DROP_MODE, input_value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING
    aom_codec_control(&codec_ctx, AV1E_SET_SKIP_POSTPROC_FILTERING, input_value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF
    aom_codec_control(&codec_ctx, AV1E_SET_AUTO_INTRA_TOOLS_OFF, input_value);

    // Fuzz aom_codec_control_typechecked_AOME_SET_CQ_LEVEL
    aom_codec_control(&codec_ctx, AOME_SET_CQ_LEVEL, input_value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_AUTO_TILES
    aom_codec_control(&codec_ctx, AV1E_SET_AUTO_TILES, input_value);

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

        LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    