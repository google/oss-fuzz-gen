// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS at aomcx.h:2381:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC at aomcx.h:2360:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE at aomcx.h:2225:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX at aomcx.h:2369:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY at aomcx.h:2255:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH at aomcx.h:2390:1 in aomcx.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
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
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int quantizer = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS(ctx, AV1E_SET_QUANTIZER_ONE_PASS, quantizer);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int rc = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(ctx, AV1E_SET_RTC_EXTERNAL_RC, rc);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int timing_info_type = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE(ctx, AV1E_SET_TIMING_INFO_TYPE, timing_info_type);
}

static void fuzz_aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int level_idx = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX(ctx, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &level_idx);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int intra_tx_only = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, intra_tx_only);
}

static void fuzz_aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int luma_cdef_strength = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(ctx, AV1E_GET_LUMA_CDEF_STRENGTH, &luma_cdef_strength);
}

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize codec context with a dummy interface
    static const aom_codec_iface_t *dummy_iface = aom_codec_av1_cx();
    codec_ctx.iface = const_cast<aom_codec_iface_t *>(dummy_iface);

    // Fuzz each API function
    fuzz_aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(&codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    