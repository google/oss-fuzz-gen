#include <cstdint>
#include <cstdlib>
#include <aom/aom_codec.h>
#include <aom/aom_decoder.h>

// Ensure C linkage for the function-under-test and related functions
extern "C" {
    aom_codec_err_t aom_codec_dec_init_ver(aom_codec_ctx_t *, aom_codec_iface_t *, const aom_codec_dec_cfg_t *, aom_codec_flags_t, int);
    aom_codec_iface_t *aom_codec_av1_dx();  // Declare the AV1 decoder interface function
    aom_codec_err_t aom_codec_destroy(aom_codec_ctx_t *ctx);  // Correctly declare the destroy function for cleanup
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();  // Using AV1 decoder interface
    aom_codec_dec_cfg_t dec_cfg;
    aom_codec_flags_t flags = 0;  // Default flags
    int ver = AOM_DECODER_ABI_VERSION;  // Use the current ABI version

    // Initialize dec_cfg with non-null values
    dec_cfg.threads = 1;  // Single-threaded decoding
    dec_cfg.w = 640;      // Default width
    dec_cfg.h = 480;      // Default height
    dec_cfg.allow_lowbitdepth = 1;  // Allow low bit depth

    // Call the function-under-test
    aom_codec_err_t result = aom_codec_dec_init_ver(&codec_ctx, iface, &dec_cfg, flags, ver);

    // Normally, you would clean up resources here, but for fuzzing, we focus on testing the function call
    aom_codec_destroy(&codec_ctx);  // Clean up resources

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
