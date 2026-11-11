// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT at aomdx.h:611:1 in aomdx.h
// aom_codec_get_global_headers at aom_encoder.c:281:18 in aom_encoder.h
// aom_codec_get_cx_data at aom_encoder.c:198:27 in aom_encoder.h
// aom_codec_get_cx_data at aom_encoder.c:198:27 in aom_encoder.h
// aom_codec_enc_config_set at aom_encoder.c:298:17 in aom_encoder.h
// aom_codec_encode at aom_encoder.c:168:17 in aom_encoder.h
// aom_codec_set_cx_data_buf at aom_encoder.c:244:17 in aom_encoder.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "aomdx.h"
#include "aom.h"
#include "aom_codec.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aom_image.h"
#include "aomcx.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t)) {
        return 0;
    }

    // Initialize codec context and configuration
    aom_codec_ctx_t codec_ctx;
    aom_codec_enc_cfg_t cfg;
    std::memcpy(&codec_ctx, Data, sizeof(aom_codec_ctx_t));
    std::memcpy(&cfg, Data + sizeof(aom_codec_ctx_t), sizeof(aom_codec_enc_cfg_t));

    // Fuzz aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT
    if (Size >= sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + 2 * sizeof(int)) {
        int width = *reinterpret_cast<const int*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t));
        int height = *reinterpret_cast<const int*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(int));
        aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT(&codec_ctx, width, height);
    }

    // Fuzz aom_codec_get_global_headers
    aom_fixed_buf_t *global_headers = aom_codec_get_global_headers(&codec_ctx);
    if (global_headers) {
        free(global_headers->buf);
        free(global_headers);
    }

    // Fuzz aom_codec_get_cx_data
    aom_codec_iter_t iter = nullptr;
    const aom_codec_cx_pkt_t *pkt = aom_codec_get_cx_data(&codec_ctx, &iter);
    while (pkt) {
        pkt = aom_codec_get_cx_data(&codec_ctx, &iter);
    }

    // Fuzz aom_codec_enc_config_set
    aom_codec_err_t err = aom_codec_enc_config_set(&codec_ctx, &cfg);
    if (err != AOM_CODEC_OK) {
        // Handle error
    }

    // Fuzz aom_codec_encode
    if (Size >= sizeof(aom_codec_ctx_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t) + sizeof(unsigned long) + sizeof(aom_enc_frame_flags_t)) {
        aom_image_t img;
        std::memcpy(&img, Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t), sizeof(aom_image_t));
        aom_codec_pts_t pts = *reinterpret_cast<const aom_codec_pts_t*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t));
        unsigned long duration = *reinterpret_cast<const unsigned long*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t));
        aom_enc_frame_flags_t flags = *reinterpret_cast<const aom_enc_frame_flags_t*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t) + sizeof(unsigned long));
        err = aom_codec_encode(&codec_ctx, &img, pts, duration, flags);
        if (err != AOM_CODEC_OK) {
            // Handle error
        }
    }

    // Fuzz aom_codec_set_cx_data_buf
    if (Size >= sizeof(aom_codec_ctx_t) + sizeof(aom_fixed_buf_t) + 2 * sizeof(unsigned int)) {
        aom_fixed_buf_t buf;
        std::memcpy(&buf, Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t) + sizeof(unsigned long) + sizeof(aom_enc_frame_flags_t), sizeof(aom_fixed_buf_t));
        unsigned int pad_before = *reinterpret_cast<const unsigned int*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t) + sizeof(unsigned long) + sizeof(aom_enc_frame_flags_t) + sizeof(aom_fixed_buf_t));
        unsigned int pad_after = *reinterpret_cast<const unsigned int*>(Data + sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t) + sizeof(aom_image_t) + sizeof(aom_codec_pts_t) + sizeof(unsigned long) + sizeof(aom_enc_frame_flags_t) + sizeof(aom_fixed_buf_t) + sizeof(unsigned int));
        err = aom_codec_set_cx_data_buf(&codec_ctx, &buf, pad_before, pad_after);
        if (err != AOM_CODEC_OK) {
            // Handle error
        }
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

        LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    