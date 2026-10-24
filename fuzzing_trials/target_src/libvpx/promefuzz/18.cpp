// This fuzz driver is generated for library libvpx, aiming to fuzz the following functions:
// vpx_codec_vp8_dx at vp8_dx_iface.c:726:1 in vp8dx.h
// vpx_codec_dec_init_ver at vpx_decoder.c:24:17 in vpx_decoder.h
// vpx_codec_error_detail at vpx_codec.c:59:13 in vpx_codec.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_build_config at vpx_config.c:10:13 in vpx_codec.h
// vpx_codec_version_str at vpx_codec.c:26:13 in vpx_codec.h
// vpx_codec_version_extra_str at vpx_codec.c:28:13 in vpx_codec.h
// vpx_codec_iface_name at vpx_codec.c:30:13 in vpx_codec.h
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
#include <vpx/vpx_decoder.h>
#include <vpx/vp8dx.h>
#include <vpx/vpx_codec.h>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_dec_cfg_t)) {
        return 0;
    }

    // Initialize the decoder context
    vpx_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Prepare the interface and configuration
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
    const vpx_codec_dec_cfg_t *cfg = reinterpret_cast<const vpx_codec_dec_cfg_t *>(Data);
    vpx_codec_flags_t flags = 0;
    int ver = VPX_DECODER_ABI_VERSION;

    // Attempt to initialize the codec
    vpx_codec_err_t res = vpx_codec_dec_init_ver(&codec_ctx, iface, cfg, flags, ver);

    // If initialization succeeded, get error details and destroy the codec context
    if (res == VPX_CODEC_OK) {
        const char *error_detail = vpx_codec_error_detail(&codec_ctx);
        if (error_detail) {
            printf("Error Detail: %s\n", error_detail);
        }
        vpx_codec_destroy(&codec_ctx);
    }

    // Retrieve build configuration and version information
    const char *build_config = vpx_codec_build_config();
    const char *version_str = vpx_codec_version_str();
    const char *version_extra_str = vpx_codec_version_extra_str();
    printf("Build Config: %s\n", build_config);
    printf("Version: %s\n", version_str);
    printf("Version Extra: %s\n", version_extra_str);

    // Get interface name if iface is valid
    const char *iface_name = vpx_codec_iface_name(iface);
    printf("Interface Name: %s\n", iface_name);

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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    