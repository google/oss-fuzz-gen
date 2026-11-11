// This fuzz driver is generated for library libvpx, aiming to fuzz the following functions:
// vpx_codec_vp8_cx at vp8_cx_iface.c:1428:1 in vp8cx.h
// vpx_codec_vp9_cx at vp9_cx_iface.c:2290:1 in vp8cx.h
// vpx_codec_enc_config_default at vpx_encoder.c:157:17 in vpx_encoder.h
// vpx_codec_enc_config_set at vpx_encoder.c:348:17 in vpx_encoder.h
// vpx_codec_enc_config_default at vpx_encoder.c:157:17 in vpx_encoder.h
// vpx_codec_enc_config_set at vpx_encoder.c:348:17 in vpx_encoder.h
// vpx_codec_enc_init_multi_ver at vpx_encoder.c:69:17 in vpx_encoder.h
// vpx_codec_enc_init_ver at vpx_encoder.c:29:17 in vpx_encoder.h
// vpx_codec_enc_init_ver at vpx_encoder.c:29:17 in vpx_encoder.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
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
#include "vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t)) {
        return 0; // Not enough data to proceed
    }

    vpx_codec_ctx_t codec_ctx;
    vpx_codec_iface_t *iface_vp8 = vpx_codec_vp8_cx();
    vpx_codec_iface_t *iface_vp9 = vpx_codec_vp9_cx();

    vpx_codec_enc_cfg_t enc_cfg;
    std::memcpy(&enc_cfg, Data, sizeof(vpx_codec_enc_cfg_t));

    vpx_rational_t dsf;
    std::memcpy(&dsf, Data + sizeof(vpx_codec_enc_cfg_t), sizeof(vpx_rational_t));

    // Initialize default configuration for VP8
    if (vpx_codec_enc_config_default(iface_vp8, &enc_cfg, 0) == VPX_CODEC_OK) {
        vpx_codec_enc_config_set(&codec_ctx, &enc_cfg);
    }

    // Initialize default configuration for VP9
    if (vpx_codec_enc_config_default(iface_vp9, &enc_cfg, 0) == VPX_CODEC_OK) {
        vpx_codec_enc_config_set(&codec_ctx, &enc_cfg);
    }

    int num_encoders = 1;
    vpx_codec_flags_t flags = 0;
    int ver = VPX_ENCODER_ABI_VERSION;

    // Initialize multi-encoder instance for VP8
    vpx_codec_enc_init_multi_ver(&codec_ctx, iface_vp8, &enc_cfg, num_encoders, flags, &dsf, ver);

    // Initialize single encoder instance for VP8
    vpx_codec_enc_init_ver(&codec_ctx, iface_vp8, &enc_cfg, flags, ver);

    // Initialize single encoder instance for VP9
    vpx_codec_enc_init_ver(&codec_ctx, iface_vp9, &enc_cfg, flags, ver);

    // Cleanup
    vpx_codec_destroy(&codec_ctx);

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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    