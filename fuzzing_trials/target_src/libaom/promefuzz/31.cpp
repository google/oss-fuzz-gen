// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_set at aom_encoder.c:298:17 in aom_encoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_get_stream_info at aom_decoder.c:75:17 in aom_decoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
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
#include "aom/aom_decoder.h"
#include "aom/aom_encoder.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include "aom/aomdx.h"
#include "aom/aomcx.h"
#include "aom/aom_integer.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_external_partition.h"

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_enc_cfg_t) + sizeof(aom_codec_stream_info_t)) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    aom_codec_enc_cfg_t enc_cfg;
    aom_codec_stream_info_t stream_info;

    // Initialize codec context with dummy values
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.iface = aom_codec_av1_cx();
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.priv = nullptr;

    // Initialize encoder configuration
    memcpy(&enc_cfg, Data, sizeof(enc_cfg));

    // Initialize stream info
    memcpy(&stream_info, Data + sizeof(enc_cfg), sizeof(stream_info));

    // Set encoder configuration
    aom_codec_err_t res = aom_codec_enc_config_set(&codec_ctx, &enc_cfg);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Control functions with dummy parameters
    int target_seq_level_idx;
    res = aom_codec_control(&codec_ctx, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &target_seq_level_idx);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    int enable_interintra_comp = 1;
    res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_COMP, enable_interintra_comp);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    int num_spatial_layers = 3;
    res = aom_codec_control(&codec_ctx, AOME_SET_NUMBER_SPATIAL_LAYERS, num_spatial_layers);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    int loopfilter_level;
    res = aom_codec_control(&codec_ctx, AOME_GET_LOOPFILTER_LEVEL, &loopfilter_level);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Get stream information
    res = aom_codec_get_stream_info(&codec_ctx, &stream_info);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Cleanup
    aom_codec_destroy(&codec_ctx);

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    