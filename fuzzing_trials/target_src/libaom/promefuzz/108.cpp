// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_DENOISE_NOISE_LEVEL at aomcx.h:2234:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT at aomcx.h:1979:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_ARNR_STRENGTH at aomcx.h:1962:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_TUNING at aomcx.h:1965:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE at aomcx.h:2237:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_CQ_LEVEL at aomcx.h:1968:1 in aomcx.h
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
#include <fstream>
#include "aomdx.h"
#include "aom.h"
#include "aom_codec.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aomcx.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Prepare data for various control functions
    int noise_level = Data[0];
    unsigned int max_inter_bitrate_pct = Data[1];
    unsigned int arnr_strength = Data[2];
    int tuning = Data[3];
    int denoise_block_size = Data[4];
    int cq_level = Data[5];

    // Dummy control ID, assuming these are defined elsewhere in the library
    int AV1E_SET_DENOISE_NOISE_LEVEL = 0;
    int AOME_SET_MAX_INTER_BITRATE_PCT = 1;
    int AOME_SET_ARNR_STRENGTH = 2;
    int AOME_SET_TUNING = 3;
    int AV1E_SET_DENOISE_BLOCK_SIZE = 4;
    int AOME_SET_CQ_LEVEL = 5;

    // Call the target functions with fuzzed inputs
    aom_codec_control_typechecked_AV1E_SET_DENOISE_NOISE_LEVEL(&codec_ctx, AV1E_SET_DENOISE_NOISE_LEVEL, noise_level);
    aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT(&codec_ctx, AOME_SET_MAX_INTER_BITRATE_PCT, max_inter_bitrate_pct);
    aom_codec_control_typechecked_AOME_SET_ARNR_STRENGTH(&codec_ctx, AOME_SET_ARNR_STRENGTH, arnr_strength);
    aom_codec_control_typechecked_AOME_SET_TUNING(&codec_ctx, AOME_SET_TUNING, tuning);
    aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(&codec_ctx, AV1E_SET_DENOISE_BLOCK_SIZE, denoise_block_size);
    aom_codec_control_typechecked_AOME_SET_CQ_LEVEL(&codec_ctx, AOME_SET_CQ_LEVEL, cq_level);

    // Clean up
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

        LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    