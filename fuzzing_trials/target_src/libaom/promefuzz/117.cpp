// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
#include <iostream>
#include <cstdint>
#include <cstring>
#include "aom.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

// Define control IDs if not already defined
#ifndef AOME_SET_MAX_INTER_BITRATE_PCT
#define AOME_SET_MAX_INTER_BITRATE_PCT 8
#endif

#ifndef AV1E_SET_DV_COST_UPD_FREQ
#define AV1E_SET_DV_COST_UPD_FREQ 9
#endif

#ifndef AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS
#define AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS 10
#endif

#ifndef AOME_SET_CQ_LEVEL
#define AOME_SET_CQ_LEVEL 11
#endif

#ifndef AV1E_SET_AUTO_TILES
#define AV1E_SET_AUTO_TILES 12
#endif

#ifndef AV1E_SET_DELTAQ_MODE
#define AV1E_SET_DELTAQ_MODE 13
#endif

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 6) {
        return 0;
    }

    // Prepare codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.name = "test_codec";

    // Extract integer values from input data
    const int *int_data = reinterpret_cast<const int*>(Data);
    int param_value1 = int_data[0];
    int param_value2 = int_data[1];
    int param_value3 = int_data[2];
    int param_value4 = int_data[3];
    int param_value5 = int_data[4];
    int param_value6 = int_data[5];

    // Fuzz aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT
    aom_codec_control(&codec_ctx, AOME_SET_MAX_INTER_BITRATE_PCT, &param_value1);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
    aom_codec_control(&codec_ctx, AV1E_SET_DV_COST_UPD_FREQ, &param_value2);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS, &param_value3);

    // Fuzz aom_codec_control_typechecked_AOME_SET_CQ_LEVEL
    aom_codec_control(&codec_ctx, AOME_SET_CQ_LEVEL, &param_value4);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_AUTO_TILES
    aom_codec_control(&codec_ctx, AV1E_SET_AUTO_TILES, &param_value5);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE
    aom_codec_control(&codec_ctx, AV1E_SET_DELTAQ_MODE, &param_value6);

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

        LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    