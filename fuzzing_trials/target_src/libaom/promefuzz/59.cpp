// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_img_alloc at aom_image.c:210:14 in aom_image.h
// aom_img_set_rect at aom_image.c:244:5 in aom_image.h
// aom_img_plane_width at aom_image.c:323:5 in aom_image.h
// aom_img_plane_height at aom_image.c:330:5 in aom_image.h
// aom_img_remove_metadata at aom_image.c:422:6 in aom_image.h
// aom_img_free at aom_image.c:314:6 in aom_image.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "aom.h"
#include "aom_image.h"

extern "C" int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_img_fmt_t) + 4 * sizeof(unsigned int)) {
        return 0;
    }

    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(Data[0]);
    unsigned int d_w = *reinterpret_cast<const unsigned int *>(Data + 1);
    unsigned int d_h = *reinterpret_cast<const unsigned int *>(Data + 1 + sizeof(unsigned int));
    unsigned int stride_align = *reinterpret_cast<const unsigned int *>(Data + 1 + 2 * sizeof(unsigned int));
    unsigned int border = *reinterpret_cast<const unsigned int *>(Data + 1 + 3 * sizeof(unsigned int));
    
    d_w = d_w % 4096; // Limit width to a reasonable size
    d_h = d_h % 4096; // Limit height to a reasonable size
    stride_align = stride_align % 64; // Limit alignment to a reasonable size
    border = border % 64; // Limit border to a reasonable size

    aom_image_t *img = aom_img_alloc(nullptr, fmt, d_w, d_h, stride_align);
    if (!img) {
        return 0;
    }

    aom_img_set_rect(img, 0, 0, d_w, d_h, border);
    int plane_width = aom_img_plane_width(img, 0);
    int plane_height = aom_img_plane_height(img, 0);

    if (img->metadata) {
        aom_img_remove_metadata(img);
    }

    aom_img_free(img);
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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    