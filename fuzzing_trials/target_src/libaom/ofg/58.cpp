#include <cstdint>
#include <cstdlib>
#include <aom/aom_codec.h>
#include <aom/aom_decoder.h>

extern "C" {

// Dummy callback functions for frame buffer operations
int get_frame_buffer(void *user_priv, size_t min_size, aom_codec_frame_buffer_t *fb) {
    // Allocate a buffer of at least min_size
    fb->data = static_cast<uint8_t*>(malloc(min_size));
    fb->size = min_size;
    return (fb->data != NULL) ? 0 : -1;
}

int release_frame_buffer(void *user_priv, aom_codec_frame_buffer_t *fb) {
    // Free the allocated buffer
    free(fb->data);
    fb->data = NULL;
    fb->size = 0;
    return 0;
}

}

extern "C" {
#include <aom/aom_decoder.h>

// Declare the codec interface for AV1
extern aom_codec_iface_t *aom_codec_av1_dx(void);
}

extern "C" {

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    aom_codec_ctx_t codec_ctx;
    aom_codec_err_t err;

    // Initialize the codec context
    err = aom_codec_dec_init(&codec_ctx, aom_codec_av1_dx(), NULL, 0);
    if (err != AOM_CODEC_OK) {
        return 0;
    }

    // Set frame buffer functions
    err = aom_codec_set_frame_buffer_functions(&codec_ctx, get_frame_buffer, release_frame_buffer, NULL);
    if (err != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Decode the input data
    err = aom_codec_decode(&codec_ctx, data, size, NULL);
    if (err != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Destroy the codec context
    aom_codec_destroy(&codec_ctx);

    return 0;
}
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
