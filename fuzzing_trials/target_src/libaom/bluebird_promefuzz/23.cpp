#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include "aom/aomdx.h"
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "/src/aom/aom/aom_external_partition.h"
#include "aom/aom_decoder.h"
#include "/src/aom/aom/aom_image.h"
#include "/src/aom/aom/aomcx.h"
#include "/src/aom/aom/aom_integer.h"
#include "/src/aom/aom/aom_frame_buffer.h"
#include "/src/aom/aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t)) return 0;

    // Create a copy of the input data to avoid overwriting the const input
    std::vector<uint8_t> dataCopy(Data, Data + Size);

    // Initialize decoder interface
    aom_codec_iface_t *decoder_iface = aom_codec_av1_dx();
    if (!decoder_iface) return 0;

    // Retrieve decoder interface name
    const char *decoder_name = aom_codec_iface_name(decoder_iface);
    if (!decoder_name) return 0;

    // Initialize encoder interface for global headers
    aom_codec_ctx_t *ctx = reinterpret_cast<aom_codec_ctx_t*>(dataCopy.data());
    ctx->iface = decoder_iface;

    // Attempt to get global headers
    aom_fixed_buf_t *global_headers = aom_codec_get_global_headers(ctx);
    if (global_headers) {
        free(global_headers->buf);
        free(global_headers);
    }

    // Explore encoder initialization
    aom_codec_enc_cfg_t enc_cfg;
    aom_codec_enc_cfg_t *cfg = &enc_cfg;
    cfg->g_usage = 0;
    cfg->g_bit_depth = AOM_BITS_8;
    cfg->g_timebase = {1, 30};
    cfg->g_error_resilient = 0;
    cfg->g_pass = AOM_RC_ONE_PASS;
    cfg->rc_superres_mode = static_cast<aom_superres_mode>(0);
    cfg->rc_end_usage = AOM_VBR;
    cfg->fwd_kf_enabled = 0;
    cfg->kf_mode = AOM_KF_AUTO;

    aom_codec_err_t init_res = aom_codec_enc_init_ver(ctx, decoder_iface, cfg, 0, AOM_ENCODER_ABI_VERSION);
    if (init_res == AOM_CODEC_OK) {
        aom_codec_destroy(ctx);
    }

    // Set frame buffer functions
    aom_codec_err_t fb_res = aom_codec_set_frame_buffer_functions(ctx, nullptr, nullptr, nullptr);
    if (fb_res == AOM_CODEC_OK) {
        aom_codec_destroy(ctx);
    }

    // Retrieve codec capabilities
    aom_codec_caps_t caps = aom_codec_get_caps(decoder_iface);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
