#include <string.h>
#include <sys/stat.h>
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
#include <cstdlib>
#include "/src/libvpx/vpx/vp8cx.h"
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "vpx/vp8dx.h"

static void fuzz_vpx_codec_build_config() {
    const char *config = vpx_codec_build_config();
    if (config) {
        // Process the config string (for fuzzing purposes, just print it)
        printf("Build Config: %s\n", config);
    }
}

static void fuzz_vpx_codec_version_str() {
    const char *version_str = vpx_codec_version_str();
    if (version_str) {
        // Process the version string (for fuzzing purposes, just print it)
        printf("Version String: %s\n", version_str);
    }
}

static void fuzz_vpx_codec_version_extra_str() {
    const char *version_extra_str = vpx_codec_version_extra_str();
    if (version_extra_str) {
        // Process the version extra string (for fuzzing purposes, just print it)
        printf("Version Extra String: %s\n", version_extra_str);
    }
}

static void fuzz_vpx_codec_version() {
    int version = vpx_codec_version();
    // Process the version integer (for fuzzing purposes, just print it)
    printf("Version: %d\n", version);
}

static void fuzz_vpx_codec_enc_init_multi_ver(vpx_codec_ctx_t *ctx, vpx_codec_iface_t *iface,
                                              const vpx_codec_enc_cfg_t *cfg, int num_enc,
                                              vpx_codec_flags_t flags, const vpx_rational_t *dsf, int ver) {
    vpx_codec_err_t res = vpx_codec_enc_init_multi_ver(ctx, iface, cfg, num_enc, flags, dsf, ver);
    if (res != VPX_CODEC_OK) {
        const char *error_detail = vpx_codec_error_detail(ctx);
        if (error_detail) {
            printf("Error Detail: %s\n", error_detail);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t) + sizeof(int)) {
        return 0;
    }

    vpx_codec_ctx_t ctx;
    memset(&ctx, 0, sizeof(vpx_codec_ctx_t)); // Properly initialize the codec context
    vpx_codec_enc_cfg_t cfg;
    vpx_rational_t dsf;
    int ver = VPX_ENCODER_ABI_VERSION;

    memcpy(&cfg, Data, sizeof(vpx_codec_enc_cfg_t));
    memcpy(&dsf, Data + sizeof(vpx_codec_enc_cfg_t), sizeof(vpx_rational_t));
    memcpy(&ver, Data + sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t), sizeof(int));

    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    int num_enc = 1;
    vpx_codec_flags_t flags = 0;

    fuzz_vpx_codec_build_config();
    fuzz_vpx_codec_version_str();
    fuzz_vpx_codec_version_extra_str();
    fuzz_vpx_codec_version();
    fuzz_vpx_codec_enc_init_multi_ver(&ctx, iface, &cfg, num_enc, flags, &dsf, ver);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
