#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "vpx/vpx_decoder.h"

extern "C" {
    #include "vpx/vpx_decoder.h"
    #include "vpx/vp8dx.h" // Include the header for vpx_codec_vp8_dx
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Declare and initialize the codec context
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_err_t err;

    // Initialize the codec context with a decoder interface
    err = vpx_codec_dec_init(&codec_ctx, vpx_codec_vp8_dx(), NULL, 0);
    if (err != VPX_CODEC_OK) {
        return 0; // Exit if initialization fails
    }

    // Declare and initialize the stream info structure
    vpx_codec_stream_info_t stream_info;
    stream_info.sz = sizeof(vpx_codec_stream_info_t);

    // Call the function-under-test
    vpx_codec_err_t result = vpx_codec_get_stream_info(&codec_ctx, &stream_info);

    // Clean up the codec context
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
