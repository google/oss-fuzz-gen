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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + sizeof(int) + sizeof(unsigned int)) {
        return 0; // Not enough data to proceed
    }

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.iface = aom_codec_av1_cx();
    
    int control_id;
    memcpy(&control_id, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    unsigned int control_value;
    memcpy(&control_value, Data, sizeof(unsigned int));
    Data += sizeof(unsigned int);
    Size -= sizeof(unsigned int);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_V
    aom_codec_err_t res = aom_codec_control(&codec_ctx, AV1E_SET_QM_V, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
    res = aom_codec_control(&codec_ctx, AV1E_SET_DV_COST_UPD_FREQ, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
    }

    // Fuzz aom_codec_control_typechecked_AOME_SET_MAX_INTRA_BITRATE_PCT
    res = aom_codec_control(&codec_ctx, AOME_SET_MAX_INTRA_BITRATE_PCT, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP
    res = aom_codec_control(&codec_ctx, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_TIER_MASK
    res = aom_codec_control(&codec_ctx, AV1E_SET_TIER_MASK, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX
    res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, control_value);
    if (res != AOM_CODEC_OK) {
        // Handle error if necessary
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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    