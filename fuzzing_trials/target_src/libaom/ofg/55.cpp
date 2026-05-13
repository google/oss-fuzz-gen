extern "C" {
    #include <aom/aom_codec.h>
    #include <aom/aom_encoder.h> // Include the encoder header for encoder functions
    #include <aom/aomcx.h> // Include the header for codec interface definitions
    #include <string.h> // Include for memcpy function
}

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx(); // Using AV1 codec interface for demonstration
    aom_codec_err_t res;

    // Initialize codec context with dummy values
    aom_codec_enc_cfg_t cfg;
    aom_codec_enc_config_default(iface, &cfg, 0);

    // Set some basic configuration options
    cfg.g_w = 640; // width
    cfg.g_h = 480; // height
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30; // framerate

    res = aom_codec_enc_init(&codec_ctx, iface, &cfg, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Prepare a dummy image
    aom_image_t img;
    if (!aom_img_alloc(&img, AOM_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1)) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Copy the fuzzing data into the image buffer
    size_t copy_size = size < img.sz ? size : img.sz;
    memcpy(img.planes[0], data, copy_size);

    // Encode the image
    res = aom_codec_encode(&codec_ctx, &img, 0, 1, 0);
    if (res != AOM_CODEC_OK) {
        aom_img_free(&img);
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Retrieve the encoded data
    aom_codec_iter_t iter = NULL;
    const aom_codec_cx_pkt_t *pkt;
    while ((pkt = aom_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == AOM_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame packet if needed
        }
    }

    // Clean up
    aom_img_free(&img);
    aom_codec_destroy(&codec_ctx);

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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
