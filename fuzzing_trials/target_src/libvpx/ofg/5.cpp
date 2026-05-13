#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <vpx/vpx_codec.h>
    #include <vpx/vpx_encoder.h>
    #include <vpx/vp8cx.h> // Include the specific header for VP8 encoder
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;

    // Initialize the codec context
    if (vpx_codec_enc_init(&codec, vpx_codec_vp8_cx(), NULL, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Simulate encoding a frame to generate some data
    vpx_image_t img;
    if (vpx_img_alloc(&img, VPX_IMG_FMT_I420, 640, 480, 1) == NULL) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Encode the image
    if (vpx_codec_encode(&codec, &img, 0, 1, 0, VPX_DL_REALTIME) != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Fuzz the function-under-test
    pkt = vpx_codec_get_cx_data(&codec, &iter);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
