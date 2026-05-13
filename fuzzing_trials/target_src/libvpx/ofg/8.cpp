#include <cstdint>
#include <cstdlib>
#include <vpx/vpx_codec.h>
#include <vpx/vpx_decoder.h>

extern "C" {

// Dummy callback functions for frame buffer operations
int get_frame_buffer_cb(void *user_priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
    if (fb == NULL) {
        return -1;
    }
    fb->data = static_cast<uint8_t*>(malloc(min_size));
    fb->size = min_size;
    return (fb->data != NULL) ? 0 : -1;
}

int release_frame_buffer_cb(void *user_priv, vpx_codec_frame_buffer_t *fb) {
    if (fb && fb->data) {
        free(fb->data);
        fb->data = NULL;
    }
    return 0;
}

// Declare the codec interface function
const vpx_codec_iface_t *vpx_codec_vp8_dx(void);

}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_err_t err;

    // Initialize the codec context to avoid passing NULL
    err = vpx_codec_dec_init(&codec_ctx, vpx_codec_vp8_dx(), NULL, 0);
    if (err != VPX_CODEC_OK) {
        return 0;
    }

    // Call the function-under-test
    err = vpx_codec_set_frame_buffer_functions(&codec_ctx, get_frame_buffer_cb, release_frame_buffer_cb, NULL);

    // Decode the input data
    if (err == VPX_CODEC_OK) {
        err = vpx_codec_decode(&codec_ctx, data, size, NULL, 0);
    }

    // Destroy the codec context to clean up
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
