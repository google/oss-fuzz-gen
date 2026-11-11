// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_img_alloc at aom_image.c:210:14 in aom_image.h
// aom_img_set_rect at aom_image.c:244:5 in aom_image.h
// aom_img_remove_metadata at aom_image.c:422:6 in aom_image.h
// aom_img_free at aom_image.c:314:6 in aom_image.h
// aom_img_wrap at aom_image.c:226:14 in aom_image.h
// aom_img_remove_metadata at aom_image.c:422:6 in aom_image.h
// aom_img_free at aom_image.c:314:6 in aom_image.h
// aom_img_alloc_with_border at aom_image.c:235:14 in aom_image.h
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
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "aom_image.h"
#include "aom.h"

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 21) {
        return 0;
    }

    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(Data[0]);
    unsigned int d_w = (Data[1] << 24) | (Data[2] << 16) | (Data[3] << 8) | Data[4];
    unsigned int d_h = (Data[5] << 24) | (Data[6] << 16) | (Data[7] << 8) | Data[8];
    unsigned int align = (Data[9] << 24) | (Data[10] << 16) | (Data[11] << 8) | Data[12];
    unsigned int stride_align = (Data[13] << 24) | (Data[14] << 16) | (Data[15] << 8) | Data[16];
    unsigned int border = (Data[17] << 24) | (Data[18] << 16) | (Data[19] << 8) | Data[20];

    aom_image_t *img = nullptr;
    img = aom_img_alloc(img, fmt, d_w, d_h, align);
    if (img) {
        aom_img_set_rect(img, 0, 0, d_w, d_h, border);
        aom_img_remove_metadata(img);
        aom_img_free(img);
    }

    unsigned char *img_data = new unsigned char[d_w * d_h * 3 / 2];
    aom_image_t *wrapped_img = aom_img_wrap(nullptr, fmt, d_w, d_h, stride_align, img_data);
    if (wrapped_img) {
        aom_img_remove_metadata(wrapped_img);
        aom_img_free(wrapped_img);
    }
    delete[] img_data;

    aom_image_t *border_img = aom_img_alloc_with_border(nullptr, fmt, d_w, d_h, align, align, border);
    if (border_img) {
        aom_img_remove_metadata(border_img);
        aom_img_free(border_img);
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    