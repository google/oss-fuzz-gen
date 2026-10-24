#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the string.h library for memcpy

extern "C" {
    #include <vpx/vpx_codec.h>
    #include <vpx/vpx_encoder.h>
    #include <vpx/vp8cx.h>
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec;
    vpx_codec_err_t res;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t img;
    vpx_codec_pts_t pts = 1; // Example PTS value
    unsigned long duration = 1; // Example duration
    vpx_enc_frame_flags_t flags = 0; // Example flags
    vpx_enc_deadline_t deadline = VPX_DL_REALTIME; // Example deadline

    // Initialize codec configuration
    if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg, 0)) {
        return 0;
    }

    // Initialize codec
    if (vpx_codec_enc_init(&codec, vpx_codec_vp8_cx(), &cfg, 0)) {
        return 0;
    }

    // Initialize image
    if (!vpx_img_alloc(&img, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1)) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Fill the image with fuzz data
    size_t img_data_size = img.d_w * img.d_h * 3 / 2; // Assuming I420 format
    if (size < img_data_size) {
        img_data_size = size;
    }
    memcpy(img.planes[0], data, img_data_size);

    // Encode the image
    res = vpx_codec_encode(&codec, &img, pts, duration, flags, deadline);

    // Clean up
    vpx_img_free(&img);
    vpx_codec_destroy(&codec);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
