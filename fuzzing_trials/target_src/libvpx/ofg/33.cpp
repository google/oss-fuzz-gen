#include <stdint.h>
#include <stddef.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8cx.h>

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_ctx_t codec;
    vpx_image_t raw;
    unsigned int width = 320;
    unsigned int height = 240;
    unsigned int usage = 0; // Default usage

    // Ensure that the function is called with non-null parameters
    if (iface == NULL) {
        return 0;
    }

    // Call the function-under-test
    vpx_codec_err_t res = vpx_codec_enc_config_default(iface, &cfg, usage);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    cfg.g_w = width;
    cfg.g_h = height;
    cfg.rc_target_bitrate = 1000;

    if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, width, height, 1)) {
        return 0;
    }

    if (vpx_codec_enc_init(&codec, iface, &cfg, 0)) {
        vpx_img_free(&raw);
        return 0;
    }

    // Feed the input data into the encoder
    if (vpx_codec_encode(&codec, &raw, 0, 1, 0, VPX_DL_REALTIME)) {
        vpx_codec_destroy(&codec);
        vpx_img_free(&raw);
        return 0;
    }

    // Clean up
    vpx_codec_destroy(&codec);
    vpx_img_free(&raw);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
