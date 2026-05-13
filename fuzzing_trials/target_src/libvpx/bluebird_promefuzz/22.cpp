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
#include <stdint.h>
#include <stddef.h>
#include <cstdio>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "/src/libvpx/vpx/vpx_image.h"

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_ctx_t)) return 0;

    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    if (!iface) return 0;

    const char *iface_name = vpx_codec_iface_name(iface);
    if (iface_name) {
        printf("Interface Name: %s\n", iface_name);
    }

    vpx_image_t *image = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, 640, 480, 1);
    if (!image) return 0;

    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t res = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(image);
        return 0;
    }

    const char *error_string = vpx_codec_err_to_string(res);
    if (error_string) {
        printf("Error String: %s\n", error_string);
    }

    vpx_codec_ctx_t codec;
    res = vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(image);
        return 0;
    }

    res = vpx_codec_encode(&codec, image, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        vpx_img_free(image);
        return 0;
    }

    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt = vpx_codec_get_cx_data(&codec, &iter);
    if (pkt) {
        printf("Packet kind: %d\n", pkt->kind);
    }

    vpx_codec_destroy(&codec);
    vpx_img_free(image);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
