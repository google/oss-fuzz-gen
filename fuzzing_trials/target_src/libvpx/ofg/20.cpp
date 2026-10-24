#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <vpx/vpx_decoder.h>
    #include <vpx/vp8dx.h>
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx(); // Use VP8 decoder interface
    vpx_codec_dec_cfg_t dec_cfg;
    vpx_codec_flags_t flags = 0; // No special flags
    int ver = VPX_DECODER_ABI_VERSION; // Use the correct ABI version

    // Initialize the decoder configuration with non-NULL values
    dec_cfg.threads = 1; // Use one thread
    dec_cfg.w = 640; // Set a default width
    dec_cfg.h = 480; // Set a default height

    // Call the function-under-test
    vpx_codec_err_t result = vpx_codec_dec_init_ver(&codec_ctx, iface, &dec_cfg, flags, ver);

    // Return 0 as required by the fuzzer
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
