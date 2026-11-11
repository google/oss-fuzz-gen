#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h" // Include the header that defines vpx_codec_vp8_dx()

// Dummy callback function
void put_slice_callback(void *user_priv, const vpx_image_t *img, const vpx_image_rect_t *valid, const vpx_image_rect_t *update) {
    // This is just a placeholder for the actual callback functionality
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Exit early if input size is zero
    }

    vpx_codec_ctx_t codec_ctx;
    vpx_codec_err_t result;
    void *user_priv = (void *)data; // Use the data pointer as user_priv for testing

    // Initialize codec context
    result = vpx_codec_dec_init(&codec_ctx, vpx_codec_vp8_dx(), NULL, 0);
    if (result != VPX_CODEC_OK) {
        return 0; // Exit if initialization fails
    }

    // Register the callback
    result = vpx_codec_register_put_slice_cb(&codec_ctx, put_slice_callback, user_priv);

    // Decode the input data
    result = vpx_codec_decode(&codec_ctx, data, size, NULL, 0);
    if (result != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec_ctx);
        return 0; // Exit if decoding fails
    }

    // Get the decoded frame
    vpx_codec_iter_t iter = NULL;
    const vpx_image_t *img = vpx_codec_get_frame(&codec_ctx, &iter);

    // Optionally, process the image here if needed

    // Destroy codec context
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
