// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA at aomcx.h:2192:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_REF_FRAME_MVS at aomcx.h:2144:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET at aomcx.h:2246:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ at aomcx.h:2153:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA at aomcx.h:2321:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_COMP_PRED at aomcx.h:2339:1 in aomcx.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
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
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA(codec, AV1E_SET_ENABLE_PAETH_INTRA, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_REF_FRAME_MVS(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_REF_FRAME_MVS(codec, AV1E_SET_ENABLE_REF_FRAME_MVS, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int set_value = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(codec, AV1E_SET_REDUCED_TX_TYPE_SET, set_value);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ(codec, AV1E_SET_ENABLE_CHROMA_DELTAQ, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2;
    aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA(codec, AV1E_SET_ENABLE_DIAGONAL_INTRA, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_COMP_PRED(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 3) return;
    aom_svc_ref_frame_comp_pred_t comp_pred;
    comp_pred.use_comp_pred[0] = Data[0] % 2;
    comp_pred.use_comp_pred[1] = Data[1] % 2;
    comp_pred.use_comp_pred[2] = Data[2] % 2;
    aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_COMP_PRED(codec, AV1E_SET_SVC_REF_FRAME_COMP_PRED, &comp_pred);
}

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_REF_FRAME_MVS(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_DIAGONAL_INTRA(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_COMP_PRED(&codec, Data, Size);

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

        LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    