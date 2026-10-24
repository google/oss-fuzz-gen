// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
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
#include <iostream>
#include <fstream>
#include "aom/aomdx.h"
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_external_partition.h"
#include "aom/aom_decoder.h"
#include "aom/aomcx.h"
#include "aom/aom_integer.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_image.h"
#include "aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + 6 * sizeof(int)) {
        return 0; // Not enough data to proceed
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    codec_ctx.name = "AV1 Codec";
    codec_ctx.iface = aom_codec_av1_cx();
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.priv = nullptr;

    // Extract parameters from input data
    int frame_size_limit = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int min_cr = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int fp_mt = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int max_intra_bitrate_pct = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int bitrate_one_pass_cbr = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int auto_intra_tools_off = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    // Setting frame size limit
    aom_codec_control(&codec_ctx, AOMD_SET_FRAME_SIZE_LIMIT, frame_size_limit);

    // Setting minimum compression ratio
    aom_codec_control(&codec_ctx, AV1E_SET_MIN_CR, min_cr);

    // Setting frame parallelism mode
    aom_codec_control(&codec_ctx, AV1E_SET_FP_MT, fp_mt);

    // Setting max intra bitrate percentage
    aom_codec_control(&codec_ctx, AOME_SET_MAX_INTRA_BITRATE_PCT, max_intra_bitrate_pct);

    // Setting constant bitrate for one-pass CBR
    aom_codec_control(&codec_ctx, AV1E_SET_BITRATE_ONE_PASS_CBR, bitrate_one_pass_cbr);

    // Disabling automatic intra tools
    aom_codec_control(&codec_ctx, AV1E_SET_AUTO_INTRA_TOOLS_OFF, auto_intra_tools_off);

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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    