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
#include <cstdlib>
#include <cstring>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "vpx/vpx_decoder.h"

static vpx_codec_iface_t *choose_interface(bool encode) {
    return encode ? vpx_codec_vp8_cx() : vpx_codec_vp8_dx();
}

static void init_image(vpx_image_t &img) {
    img.fmt = VPX_IMG_FMT_I420;
    img.cs = VPX_CS_BT_601;
    img.range = VPX_CR_STUDIO_RANGE;
    img.w = 640;
    img.h = 480;
    img.stride[0] = 640;
    img.stride[1] = 320;
    img.stride[2] = 320;
    img.planes[0] = new unsigned char[640 * 480];
    img.planes[1] = new unsigned char[320 * 240];
    img.planes[2] = new unsigned char[320 * 240];
}

static void destroy_image(vpx_image_t &img) {
    delete[] img.planes[0];
    delete[] img.planes[1];
    delete[] img.planes[2];
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    vpx_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    bool is_encoder = Data[0] % 2 == 0;
    vpx_codec_iface_t *iface = choose_interface(is_encoder);

    if (is_encoder) {
        vpx_codec_enc_cfg_t enc_cfg;
        vpx_codec_enc_config_default(iface, &enc_cfg, 0);
        enc_cfg.g_timebase.num = 1;
        enc_cfg.g_timebase.den = 30;
        enc_cfg.g_w = 640;
        enc_cfg.g_h = 480;

        if (vpx_codec_enc_init_ver(&codec_ctx, iface, &enc_cfg, 0, VPX_ENCODER_ABI_VERSION) == VPX_CODEC_OK) {
            vpx_image_t img;
            init_image(img);

            vpx_codec_encode(&codec_ctx, &img, 0, 1, 0, VPX_DL_REALTIME);
            vpx_codec_destroy(&codec_ctx);

            destroy_image(img);
        }
    } else {
        vpx_codec_dec_cfg_t dec_cfg;
        dec_cfg.threads = 1;

        if (vpx_codec_dec_init_ver(&codec_ctx, iface, &dec_cfg, 0, VPX_DECODER_ABI_VERSION) == VPX_CODEC_OK) {
            vpx_codec_decode(&codec_ctx, Data, Size, nullptr, 0);
            vpx_codec_destroy(&codec_ctx);
        }
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
