// This fuzz driver is generated for library libvpx, aiming to fuzz the following functions:
// vpx_codec_dec_init_ver at vpx_decoder.c:24:17 in vpx_decoder.h
// vpx_codec_vp8_dx at vp8_dx_iface.c:726:1 in vp8dx.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_enc_init_ver at vpx_encoder.c:29:17 in vpx_encoder.h
// vpx_codec_vp8_cx at vp8_cx_iface.c:1428:1 in vp8cx.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_build_config at vpx_config.c:10:13 in vpx_codec.h
// vpx_codec_version_str at vpx_codec.c:26:13 in vpx_codec.h
// vpx_codec_version_extra_str at vpx_codec.c:28:13 in vpx_codec.h
// vpx_codec_iface_name at vpx_codec.c:30:13 in vpx_codec.h
// vpx_codec_vp8_dx at vp8_dx_iface.c:726:1 in vp8dx.h
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
#include <cstring>
#include "vp8cx.h"
#include "vp8dx.h"
#include "vpx_codec.h"
#include "vpx_encoder.h"
#include "vpx_decoder.h"

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_codec_dec_cfg_t) + sizeof(vpx_codec_enc_cfg_t)) {
        return 0;
    }

    // Initialize decoder context
    vpx_codec_ctx_t dec_ctx;
    vpx_codec_dec_cfg_t dec_cfg;
    vpx_codec_flags_t dec_flags = 0;
    int dec_ver = VPX_DECODER_ABI_VERSION;

    std::memcpy(&dec_ctx, Data, sizeof(vpx_codec_ctx_t));
    std::memcpy(&dec_cfg, Data + sizeof(vpx_codec_ctx_t), sizeof(vpx_codec_dec_cfg_t));

    vpx_codec_err_t dec_err = vpx_codec_dec_init_ver(&dec_ctx, vpx_codec_vp8_dx(), &dec_cfg, dec_flags, dec_ver);
    if (dec_err == VPX_CODEC_OK) {
        vpx_codec_destroy(&dec_ctx);
    }

    // Initialize encoder context
    vpx_codec_ctx_t enc_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_codec_flags_t enc_flags = 0;
    int enc_ver = VPX_ENCODER_ABI_VERSION;

    std::memcpy(&enc_ctx, Data, sizeof(vpx_codec_ctx_t));
    std::memcpy(&enc_cfg, Data + sizeof(vpx_codec_ctx_t), sizeof(vpx_codec_enc_cfg_t));

    vpx_codec_err_t enc_err = vpx_codec_enc_init_ver(&enc_ctx, vpx_codec_vp8_cx(), &enc_cfg, enc_flags, enc_ver);
    if (enc_err == VPX_CODEC_OK) {
        vpx_codec_destroy(&enc_ctx);
    }

    // Retrieve build configuration
    const char *build_config = vpx_codec_build_config();

    // Retrieve version strings
    const char *version_str = vpx_codec_version_str();
    const char *version_extra_str = vpx_codec_version_extra_str();

    // Retrieve interface name
    const char *iface_name = vpx_codec_iface_name(vpx_codec_vp8_dx());

    // Write data to a dummy file if needed
    FILE *dummy_file = std::fopen("./dummy_file", "wb");
    if (dummy_file) {
        std::fwrite(Data, 1, Size, dummy_file);
        std::fclose(dummy_file);
    }

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    