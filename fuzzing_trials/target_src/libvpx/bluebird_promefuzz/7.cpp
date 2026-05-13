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
#include <cstring>
#include <iostream>
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "/src/libvpx/vpx/vpx_image.h"
#include "vpx/vpx_decoder.h"

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize codec context
    vpx_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
    if (!iface) return 0;

    if (vpx_codec_dec_init(&codec_ctx, iface, nullptr, 0)) {
        return 0;
    }

    // Prepare an iterator for vpx_codec_get_frame
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;

    // Call vpx_codec_get_frame
    img = vpx_codec_get_frame(&codec_ctx, &iter);

    // Call vpx_codec_get_preview_frame
    const vpx_image_t *preview_img = vpx_codec_get_preview_frame(&codec_ctx);

    // Prepare an image for vpx_img_set_rect
    vpx_image_t image;
    memset(&image, 0, sizeof(image));
    image.w = 640;
    image.h = 480;
    image.planes[0] = (unsigned char *)malloc(640 * 480);

    if (image.planes[0]) {
        // Call vpx_img_set_rect
        vpx_img_set_rect(&image, 0, 0, 640, 480);
        free(image.planes[0]);
        image.planes[0] = nullptr; // Avoid double free
    }

    // Prepare data for vpx_img_wrap
    unsigned char *img_data = (unsigned char *)malloc(640 * 480 * 3 / 2);
    vpx_image_t *wrapped_img = nullptr;
    if (img_data) {
        vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;
        wrapped_img = vpx_img_wrap(nullptr, fmt, 640, 480, 1, img_data);
        if (wrapped_img) {
            vpx_img_flip(wrapped_img);
        }
    }

    // Prepare image for vpx_img_alloc
    vpx_image_t *allocated_img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, 640, 480, 1);
    if (allocated_img) {
        vpx_img_free(allocated_img);
    }

    // Cleanup wrapped image data
    if (wrapped_img) {
        vpx_img_free(wrapped_img);
    } else if (img_data) {
        free(img_data);
    }

    // Cleanup codec context
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
