#include <cstdint>
#include <cstdlib>
#include <aom/aom_codec.h>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>

extern "C" {

// Define dummy callback functions
int get_frame_buffer_cb(void *priv, size_t min_size, aom_codec_frame_buffer_t *fb) {
    // Dummy implementation
    if (fb == NULL || min_size == 0) {
        return -1;
    }
    fb->data = static_cast<uint8_t *>(malloc(min_size)); // Cast to uint8_t*
    if (fb->data == NULL) {
        return -1; // Return error if malloc fails
    }
    fb->size = min_size;
    return 0;
}

int release_frame_buffer_cb(void *priv, aom_codec_frame_buffer_t *fb) {
    // Dummy implementation
    if (fb == NULL || fb->data == NULL) {
        return -1;
    }
    free(fb->data);
    fb->data = NULL;
    fb->size = 0;
    return 0;
}

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    aom_codec_ctx_t codec_ctx;
    aom_codec_err_t res;
    
    // Initialize codec context
    res = aom_codec_dec_init(&codec_ctx, aom_codec_av1_dx(), NULL, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Call the function under test
    res = aom_codec_set_frame_buffer_functions(&codec_ctx, get_frame_buffer_cb, release_frame_buffer_cb, NULL);

    // Feed data to the codec
    if (size > 0) {
        res = aom_codec_decode(&codec_ctx, data, size, NULL);
    }

    // Destroy codec context
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
