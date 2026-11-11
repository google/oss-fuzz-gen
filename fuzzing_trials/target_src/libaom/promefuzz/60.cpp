// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_ENABLE_MOTION_VECTOR_UNIT_TEST at aomcx.h:2222:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING at aomcx.h:2375:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ at aomcx.h:2324:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_ENABLE_RATE_GUIDE_DELTAQ at aomcx.h:2384:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_TIER_MASK at aomcx.h:2279:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SINGLE_TILE_DECODING at aomcx.h:2219:1 in aomcx.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
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
#include "aomcx.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 2) return 0;

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    int control_id = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    unsigned int arg = *reinterpret_cast<const unsigned int*>(Data);

    aom_codec_err_t res;
    switch (control_id) {
    case 0:
        res = aom_codec_control_typechecked_AV1E_ENABLE_MOTION_VECTOR_UNIT_TEST(&codec, AV1E_ENABLE_MOTION_VECTOR_UNIT_TEST, arg);
        break;
    case 1:
        res = aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING(&codec, AV1E_SET_SKIP_POSTPROC_FILTERING, arg);
        break;
    case 2:
        res = aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ(&codec, AV1E_SET_DV_COST_UPD_FREQ, arg);
        break;
    case 3:
        res = aom_codec_control_typechecked_AV1E_ENABLE_RATE_GUIDE_DELTAQ(&codec, AV1E_ENABLE_RATE_GUIDE_DELTAQ, arg);
        break;
    case 4:
        res = aom_codec_control_typechecked_AV1E_SET_TIER_MASK(&codec, AV1E_SET_TIER_MASK, arg);
        break;
    case 5:
        res = aom_codec_control_typechecked_AV1E_SET_SINGLE_TILE_DECODING(&codec, AV1E_SET_SINGLE_TILE_DECODING, arg);
        break;
    default:
        return 0;
    }

    if (res != AOM_CODEC_OK) {
        fprintf(stderr, "Codec control error: %s\n", aom_codec_err_to_string(res));
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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    