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
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    int noise_level = Data[0] % 100; // Assuming noise level is between 0 and 99
    int enable_dist_wtd_comp = Data[1] % 2; // 0 or 1
    int screen_content_mode = Data[2] % 2; // 0 or 1
    int enable_directional_intra = Data[3] % 2; // 0 or 1
    int reduced_reference_set = Data[4] % 2; // 0 or 1
    int intra_dct_only = Data[5] % 2; // 0 or 1

    if (aom_codec_enc_init(&codec_ctx, iface, nullptr, 0)) {
        std::cerr << "Failed to initialize codec" << std::endl;
        return 0;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DENOISE_NOISE_LEVEL
    aom_codec_control(&codec_ctx, AV1E_SET_DENOISE_NOISE_LEVEL, noise_level);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_DIST_WTD_COMP
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DIST_WTD_COMP, enable_dist_wtd_comp);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE
    aom_codec_control(&codec_ctx, AV1E_SET_SCREEN_CONTENT_DETECTION_MODE, screen_content_mode);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_DIRECTIONAL_INTRA
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DIRECTIONAL_INTRA, enable_directional_intra);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET
    aom_codec_control(&codec_ctx, AV1E_SET_REDUCED_REFERENCE_SET, reduced_reference_set);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY
    aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DCT_ONLY, intra_dct_only);

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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    