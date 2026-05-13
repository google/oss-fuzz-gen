// This fuzz driver is generated for library libvpx, aiming to fuzz the following functions:
// vpx_codec_encode at vpx_encoder.c:193:17 in vpx_encoder.h
// vpx_codec_encode at vpx_encoder.c:193:17 in vpx_encoder.h
// vpx_codec_enc_config_set at vpx_encoder.c:348:17 in vpx_encoder.h
// vpx_codec_vp8_cx at vp8_cx_iface.c:1428:1 in vp8cx.h
// vpx_codec_peek_stream_info at vpx_decoder.c:65:17 in vpx_decoder.h
// vpx_codec_decode at vpx_decoder.c:104:17 in vpx_decoder.h
// vpx_codec_decode at vpx_decoder.c:104:17 in vpx_decoder.h
// vpx_codec_vp8_cx at vp8_cx_iface.c:1428:1 in vp8cx.h
// vpx_codec_enc_init_ver at vpx_encoder.c:29:17 in vpx_encoder.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "vp8cx.h"
#include "vp8dx.h"
#include "vpx_codec.h"
#include "vpx_encoder.h"
#include "vpx_decoder.h"
}

#include <cstdint>
#include <cstring>

static void fuzz_vpx_codec_encode(vpx_codec_ctx_t *ctx) {
    vpx_image_t img;
    std::memset(&img, 0, sizeof(img));
    img.fmt = VPX_IMG_FMT_I420;
    img.w = 640;
    img.h = 480;

    vpx_codec_pts_t pts = 0;
    unsigned long duration = 1;
    vpx_enc_frame_flags_t flags = 0;
    vpx_enc_deadline_t deadline = 0;

    vpx_codec_encode(ctx, &img, pts, duration, flags, deadline);
    vpx_codec_encode(ctx, nullptr, pts, duration, flags, deadline);
}

static void fuzz_vpx_codec_enc_config_set(vpx_codec_ctx_t *ctx) {
    vpx_codec_enc_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.g_w = 640;
    cfg.g_h = 480;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;

    vpx_codec_enc_config_set(ctx, &cfg);
}

static void fuzz_vpx_codec_peek_stream_info(const uint8_t *data, size_t size) {
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    vpx_codec_stream_info_t si;
    si.sz = sizeof(si);

    vpx_codec_peek_stream_info(iface, data, size, &si);
}

static void fuzz_vpx_codec_decode(vpx_codec_ctx_t *ctx, const uint8_t *data, size_t size) {
    vpx_codec_decode(ctx, data, size, nullptr, 0);
    vpx_codec_decode(ctx, nullptr, 0, nullptr, 0);
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    vpx_codec_ctx_t ctx;
    std::memset(&ctx, 0, sizeof(ctx));

    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    vpx_codec_err_t res = vpx_codec_enc_init(&ctx, iface, nullptr, 0);

    if (res == VPX_CODEC_OK) {
        fuzz_vpx_codec_encode(&ctx);
        fuzz_vpx_codec_enc_config_set(&ctx);
        fuzz_vpx_codec_peek_stream_info(Data, Size);
        fuzz_vpx_codec_decode(&ctx, Data, Size);
    }

    vpx_codec_destroy(&ctx);
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
    