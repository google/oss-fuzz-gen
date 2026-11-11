#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this for memset

extern "C" {
    #include "/src/libvpx/vpx/vpx_codec.h"
    #include "vpx/vpx_decoder.h"
    #include "vpx/vp8dx.h" // Include this for vpx_codec_vp8_dx
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Initialize codec context and stream info structures
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_stream_info_t stream_info;

    // Ensure the structures are properly initialized
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    memset(&stream_info, 0, sizeof(stream_info));

    // Set some non-zero values for stream_info
    stream_info.sz = sizeof(stream_info);

    // Initialize the codec
    if (vpx_codec_dec_init(&codec_ctx, vpx_codec_vp8_dx(), NULL, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Decode the input data
    if (vpx_codec_decode(&codec_ctx, data, size, NULL, 0) != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Get stream info after decoding
    vpx_codec_err_t result = vpx_codec_get_stream_info(&codec_ctx, &stream_info);

    // Clean up
    vpx_codec_destroy(&codec_ctx);

    // Return 0 as the fuzzer's return value
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
