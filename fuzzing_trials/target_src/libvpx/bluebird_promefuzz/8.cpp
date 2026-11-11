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
extern "C" {
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "/src/libvpx/vpx/vpx_image.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int) * 3) {
        return 0; // Not enough data to proceed
    }

    // Extract parameters from Data
    unsigned int width = reinterpret_cast<const unsigned int*>(Data)[0] % 0x08000000;
    unsigned int height = reinterpret_cast<const unsigned int*>(Data)[1] % 0x08000000;
    unsigned int align = reinterpret_cast<const unsigned int*>(Data)[2] % 65536;

    // Allocate image
    vpx_image_t *img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, width, height, align);
    if (!img) {
        return 0; // Failed to allocate image
    }

    // Get codec interface
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    const char *iface_name = vpx_codec_iface_name(iface);

    // Initialize encoder configuration
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t res = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }

    // Initialize codec context
    vpx_codec_ctx_t codec;
    res = vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }

    // Perform codec control operation
    res = vpx_codec_control_(&codec, VP8E_SET_CPUUSED, 0);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        vpx_img_free(img);
        return 0;
    }

    // Cleanup
    vpx_codec_destroy(&codec);
    vpx_img_free(img);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
