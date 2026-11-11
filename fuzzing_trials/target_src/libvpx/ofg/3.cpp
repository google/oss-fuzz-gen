#include <stdint.h>
#include <stddef.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8dx.h>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec;
    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;

    // Initialize codec interface
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();

    // Initialize codec context with default configuration
    if (vpx_codec_dec_init(&codec, iface, NULL, 0)) {
        return 0; // Return if initialization fails
    }

    // Decode the input data
    if (vpx_codec_decode(&codec, data, static_cast<unsigned int>(size), NULL, 0)) {
        vpx_codec_destroy(&codec);
        return 0; // Return if decoding fails
    }

    // Retrieve the decoded frame
    img = vpx_codec_get_frame(&codec, &iter);

    // Clean up codec context
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
