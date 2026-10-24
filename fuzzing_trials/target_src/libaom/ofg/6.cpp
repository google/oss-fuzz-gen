#include <cstdint>
#include <cstdlib>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Return early if there's no data
    }

    // Initialize variables for the function-under-test
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx(); // Use AV1 decoder interface
    aom_codec_dec_cfg_t dec_cfg;
    aom_codec_flags_t flags = 0;
    int ver = AOM_DECODER_ABI_VERSION;

    // Initialize the decoder configuration with non-null values
    dec_cfg.threads = 1;
    dec_cfg.w = 640;  // Width
    dec_cfg.h = 480;  // Height
    dec_cfg.allow_lowbitdepth = 1;

    // Call the function-under-test
    aom_codec_err_t res = aom_codec_dec_init_ver(&codec_ctx, iface, &dec_cfg, flags, ver);

    if (res == AOM_CODEC_OK) {
        // Decode the input data
        aom_codec_err_t decode_res = aom_codec_decode(&codec_ctx, data, size, nullptr);

        // Clean up
        aom_codec_destroy(&codec_ctx);
    }

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
