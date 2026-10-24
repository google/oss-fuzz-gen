// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_ENABLE_ANGLE_DELTA at aomcx.h:2210:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER at aomcx.h:2126:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_TX64 at aomcx.h:2132:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA at aomcx.h:2192:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS at aomcx.h:2117:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA at aomcx.h:2321:1 in aomcx.h
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
#include "aomcx.h"
#include "aom_codec.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + 1) {
        return 0;
    }

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    // Assume the first byte controls which function to call and the rest is the parameter
    uint8_t control_function = Data[0];
    int parameter = 0;
    memcpy(&parameter, Data + 1, sizeof(int));

    aom_codec_err_t res = AOM_CODEC_OK;
    
    switch (control_function % 6) {
        case 0:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_ANGLE_DELTA(&codec, AV1E_SET_ENABLE_ANGLE_DELTA, parameter);
            break;
        case 1:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER(&codec, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, parameter);
            break;
        case 2:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_TX64(&codec, AV1E_SET_ENABLE_TX64, parameter);
            break;
        case 3:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA(&codec, AV1E_SET_ENABLE_PAETH_INTRA, parameter);
            break;
        case 4:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS(&codec, AV1E_SET_ENABLE_1TO4_PARTITIONS, parameter);
            break;
        case 5:
            res = aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA(&codec, AV1E_SET_ENABLE_DIAGONAL_INTRA, parameter);
            break;
        default:
            break;
    }

    if (res != AOM_CODEC_OK) {
        // Handle error if needed
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    