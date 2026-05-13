#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    } // Ensure there's data to work with

    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function vpx_codec_vp9_dx with vpx_codec_vp8_dx
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    vpx_codec_dec_cfg_t dec_cfg = {0}; // Default configuration
    vpx_codec_stream_info_t stream_info;
    stream_info.sz = sizeof(vpx_codec_stream_info_t);

    // Initialize the decoder context
    if (vpx_codec_dec_init_ver(&codec_ctx, iface, &dec_cfg, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
        return 0; // Initialization failed
    }

    // Peek stream info
    vpx_codec_peek_stream_info(iface, Data, static_cast<unsigned int>(Size), &stream_info);

    // Decode the data
    vpx_codec_decode(&codec_ctx, Data, static_cast<unsigned int>(Size), nullptr, 0);

    // Get stream info
    vpx_codec_get_stream_info(&codec_ctx, &stream_info);

    // Register a dummy frame callback
    auto frame_callback = [](void *user_priv, const vpx_image_t *img) {};
    vpx_codec_register_put_frame_cb(&codec_ctx, frame_callback, nullptr);

    // Signal completion of the previous frame
    vpx_codec_decode(&codec_ctx, nullptr, 0, nullptr, 0);

    // Cleanup
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
