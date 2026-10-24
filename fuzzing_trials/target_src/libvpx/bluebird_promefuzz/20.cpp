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
#include <cstring>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "vpx/vpx_decoder.h"

static vpx_codec_ctx_t* initialize_codec_context() {
    vpx_codec_ctx_t* ctx = new vpx_codec_ctx_t();
    memset(ctx, 0, sizeof(vpx_codec_ctx_t));
    return ctx;
}

static vpx_image_t* create_dummy_image() {
    vpx_image_t* img = new vpx_image_t();
    memset(img, 0, sizeof(vpx_image_t));
    img->fmt = VPX_IMG_FMT_I420;
    img->w = 640;
    img->h = 480;
    return img;
}

static void cleanup_codec_context(vpx_codec_ctx_t* ctx) {
    if (ctx) {
        delete ctx;
    }
}

static void cleanup_image(vpx_image_t* img) {
    if (img) {
        delete img;
    }
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_image_t)) {
        return 0;
    }

    vpx_codec_ctx_t* ctx = initialize_codec_context();
    vpx_image_t* img = create_dummy_image();

    // Fuzz vpx_codec_encode
    vpx_codec_pts_t pts = 0;
    unsigned long duration = 1;
    vpx_enc_frame_flags_t flags = 0;
    vpx_enc_deadline_t deadline = 0;

    vpx_codec_err_t encode_err = vpx_codec_encode(ctx, img, pts, duration, flags, deadline);
    if (encode_err != VPX_CODEC_OK) {
        fprintf(stderr, "vpx_codec_encode error: %d\n", encode_err);
    }

    // Fuzz vpx_codec_get_caps
    // Using a dummy codec interface
    vpx_codec_iface_t* iface = vpx_codec_vp8_cx();
    vpx_codec_caps_t caps = vpx_codec_get_caps(iface);
    (void)caps;

    // Fuzz vpx_codec_decode
    vpx_codec_err_t decode_err = vpx_codec_decode(ctx, Data, static_cast<unsigned int>(Size), nullptr, 0);
    if (decode_err != VPX_CODEC_OK) {
        fprintf(stderr, "vpx_codec_decode error: %d\n", decode_err);
    }

    // Fuzz vpx_codec_set_cx_data_buf
    vpx_fixed_buf_t buf;
    buf.buf = const_cast<uint8_t*>(Data);
    buf.sz = Size;
    vpx_codec_err_t set_buf_err = vpx_codec_set_cx_data_buf(ctx, &buf, 0, 0);
    if (set_buf_err != VPX_CODEC_OK) {
        fprintf(stderr, "vpx_codec_set_cx_data_buf error: %d\n", set_buf_err);
    }

    // Fuzz vpx_codec_get_global_headers
    vpx_fixed_buf_t* global_headers = vpx_codec_get_global_headers(ctx);
    (void)global_headers;

    // Fuzz vpx_codec_enc_config_set
    vpx_codec_enc_cfg_t cfg;
    memset(&cfg, 0, sizeof(vpx_codec_enc_cfg_t));
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    vpx_codec_err_t config_err = vpx_codec_enc_config_set(ctx, &cfg);
    if (config_err != VPX_CODEC_OK) {
        fprintf(stderr, "vpx_codec_enc_config_set error: %d\n", config_err);
    }

    cleanup_codec_context(ctx);
    cleanup_image(img);

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
