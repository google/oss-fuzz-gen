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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "vpx/vpx_decoder.h"

static vpx_codec_ctx_t *initialize_codec_context() {
    vpx_codec_ctx_t *ctx = static_cast<vpx_codec_ctx_t *>(malloc(sizeof(vpx_codec_ctx_t)));
    if (ctx) {
        memset(ctx, 0, sizeof(vpx_codec_ctx_t));
    }
    return ctx;
}

static vpx_image_t *initialize_image() {
    vpx_image_t *img = static_cast<vpx_image_t *>(malloc(sizeof(vpx_image_t)));
    if (img) {
        memset(img, 0, sizeof(vpx_image_t));
        img->fmt = VPX_IMG_FMT_I420;
        img->w = 640;
        img->h = 480;
    }
    return img;
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_pts_t) + sizeof(unsigned long) + sizeof(vpx_enc_frame_flags_t) + sizeof(vpx_enc_deadline_t)) {
        return 0;
    }

    vpx_codec_ctx_t *ctx = initialize_codec_context();
    vpx_image_t *img = initialize_image();
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    
    vpx_codec_pts_t pts = *reinterpret_cast<const vpx_codec_pts_t *>(Data);
    Data += sizeof(vpx_codec_pts_t);
    Size -= sizeof(vpx_codec_pts_t);

    unsigned long duration = *reinterpret_cast<const unsigned long *>(Data);
    Data += sizeof(unsigned long);
    Size -= sizeof(unsigned long);

    vpx_enc_frame_flags_t flags = *reinterpret_cast<const vpx_enc_frame_flags_t *>(Data);
    Data += sizeof(vpx_enc_frame_flags_t);
    Size -= sizeof(vpx_enc_frame_flags_t);

    vpx_enc_deadline_t deadline = *reinterpret_cast<const vpx_enc_deadline_t *>(Data);
    Data += sizeof(vpx_enc_deadline_t);
    Size -= sizeof(vpx_enc_deadline_t);

    if (ctx && img && iface) {
        // Attempt to encode
        vpx_codec_err_t res = vpx_codec_encode(ctx, img, pts, duration, flags, deadline);
        if (res != VPX_CODEC_OK) {
            const char *error_msg = vpx_codec_error(ctx);
            const char *error_detail = vpx_codec_error_detail(ctx);
            if (error_msg) {
                printf("Error: %s\n", error_msg);
            }
            if (error_detail) {
                printf("Error Detail: %s\n", error_detail);
            }
        }

        // Attempt to get global headers
        vpx_fixed_buf_t *global_headers = vpx_codec_get_global_headers(ctx);
        if (global_headers) {
            printf("Global Headers Size: %zu\n", global_headers->sz);
        }

        // Attempt to decode
        res = vpx_codec_decode(ctx, Data, static_cast<unsigned int>(Size), nullptr, 0);
        if (res != VPX_CODEC_OK) {
            const char *error_msg = vpx_codec_error(ctx);
            const char *error_detail = vpx_codec_error_detail(ctx);
            if (error_msg) {
                printf("Decode Error: %s\n", error_msg);
            }
            if (error_detail) {
                printf("Decode Error Detail: %s\n", error_detail);
            }
        }

        // Get capabilities
        vpx_codec_caps_t caps = vpx_codec_get_caps(iface);
        printf("Codec Capabilities: %ld\n", caps);
    }

    free(ctx);
    free(img);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
