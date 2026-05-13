#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <vpx/vpx_decoder.h>
    #include <vpx/vpx_codec.h>
    #include <vpx/vp8dx.h>
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec;
    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;

    // Initialize the codec context
    if (vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), NULL, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Decode the data
    if (vpx_codec_decode(&codec, data, size, NULL, 0) != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Attempt to get a frame
    img = vpx_codec_get_frame(&codec, &iter);

    // Clean up
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
