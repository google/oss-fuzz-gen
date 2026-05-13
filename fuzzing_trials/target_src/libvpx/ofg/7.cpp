#include <vpx/vpx_encoder.h>
#include <vpx/vp8cx.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t)) {
        return 0;
    }

    vpx_codec_ctx_t codec;
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    const vpx_codec_enc_cfg_t *cfg = reinterpret_cast<const vpx_codec_enc_cfg_t *>(data);
    int num_encoders = 1;
    vpx_codec_flags_t flags = 0;
    const vpx_rational_t *dsf = reinterpret_cast<const vpx_rational_t *>(data + sizeof(vpx_codec_enc_cfg_t));
    int ver = VPX_ENCODER_ABI_VERSION;

    vpx_codec_err_t result = vpx_codec_enc_init_multi_ver(&codec, iface, cfg, num_encoders, flags, dsf, ver);

    // Clean up if initialization was successful
    if (result == VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
