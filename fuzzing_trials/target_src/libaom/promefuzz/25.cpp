// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_img_wrap at aom_image.c:226:14 in aom_image.h
// aom_img_flip at aom_image.c:295:6 in aom_image.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "aom.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_image.h"
#include "aom_integer.h"
#include "aomdx.h"
#include "aomcx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_img_fmt_t) + 3 * sizeof(unsigned int)) {
        return 0;
    }

    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(Data[0]);
    unsigned int d_w = Data[1] % 128; // Limit width to a small number for fuzzing
    unsigned int d_h = Data[2] % 128; // Limit height to a small number for fuzzing
    unsigned int stride_align = Data[3] % 64; // Limit stride alignment to a small number

    unsigned char *img_data = new unsigned char[d_w * d_h * 3 / 2]; // Allocate minimal buffer

    aom_image_t *img = nullptr;
    img = aom_img_wrap(img, fmt, d_w, d_h, stride_align, img_data);

    if (img != nullptr) {
        aom_img_flip(img);
        aom_img_free(img);
    }

    delete[] img_data;

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    