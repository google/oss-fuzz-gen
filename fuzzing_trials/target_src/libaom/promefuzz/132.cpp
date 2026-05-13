// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
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

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *Data, size_t Size) {
    if (Size < 6) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    codec_ctx.name = "AV1 Codec";
    codec_ctx.iface = nullptr; // Assuming iface is not needed for this test
    codec_ctx.err = static_cast<aom_codec_err_t>(0);
    codec_ctx.init_flags = 0;
    codec_ctx.config.enc = nullptr; // Assuming enc is not needed for this test
    codec_ctx.priv = nullptr;

    // Use the data to determine control values
    int control_value = Data[0] % 256;
    int enable_palette = Data[1] % 2;
    int enable_adaptive_sharpness = Data[2] % 2;
    int complexity_value = Data[3] % 256;
    int enable_dist_8x8 = Data[4] % 2;
    int mtu_value = Data[5] % 65536;

    // Fuzz AV1E_SET_DV_COST_UPD_FREQ
    aom_codec_control(&codec_ctx, AV1E_SET_DV_COST_UPD_FREQ, control_value);

    // Fuzz AV1E_SET_ENABLE_PALETTE
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_PALETTE, enable_palette);

    // Fuzz AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS, enable_adaptive_sharpness);

    // Fuzz AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP
    aom_codec_control(&codec_ctx, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, complexity_value);

    // Fuzz AV1E_SET_ENABLE_RECT_TX (assuming this is the intended control)
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, enable_dist_8x8);

    // Fuzz AV1E_SET_MTU
    aom_codec_control(&codec_ctx, AV1E_SET_MTU, mtu_value);

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

        LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    