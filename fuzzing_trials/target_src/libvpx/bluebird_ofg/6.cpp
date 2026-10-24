#include <sys/stat.h>
#include <string.h>
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the parameters
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t)) {
        return 0;
    }

    // Initialize the codec context
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();

    // Initialize the encoder configuration
    const vpx_codec_enc_cfg_t *cfg = reinterpret_cast<const vpx_codec_enc_cfg_t *>(data);

    // Extract the rational data from the input
    const vpx_rational_t *rational = reinterpret_cast<const vpx_rational_t *>(data + sizeof(vpx_codec_enc_cfg_t));

    // Initialize other parameters
    int num_encoders = 1; // Use a single encoder for simplicity
    vpx_codec_flags_t flags = 0; // No special flags
    int ver = VPX_ENCODER_ABI_VERSION; // Use the current ABI version

    // Call the function-under-test
    vpx_codec_err_t result = vpx_codec_enc_init_multi_ver(&codec_ctx, iface, cfg, num_encoders, flags, rational, ver);

    // Clean up (if necessary)
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
