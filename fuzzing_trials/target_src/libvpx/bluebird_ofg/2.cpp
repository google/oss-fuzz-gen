#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libvpx/vpx/vpx_codec.h"
    #include "/src/libvpx/vpx/vpx_encoder.h"
    #include "/src/libvpx/vpx/vp8cx.h" // Include the specific header for VP8 codec
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    vpx_codec_ctx_t codec_ctx;
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t res;

    // Initialize codec configuration
    res = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Adjust the configuration based on input data
    cfg.g_w = data[0] % 256 + 1; // Ensure width is at least 1
    cfg.g_h = data[0] % 256 + 1; // Ensure height is at least 1

    // Initialize codec context
    res = vpx_codec_enc_init(&codec_ctx, iface, &cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Create a dummy image
    vpx_image_t img;
    if (!vpx_img_alloc(&img, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1)) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Feed the image to the encoder
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 4 of vpx_codec_encode
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 5 of vpx_codec_encode
    res = vpx_codec_encode(&codec_ctx, &img, 0, 1, VPX_EFLAG_CALCULATE_PSNR, size);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (res != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Retrieve the encoded data
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame (e.g., save or analyze)
        }
    }

    // Clean up
    vpx_img_free(&img);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
