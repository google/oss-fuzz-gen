// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR at aomcx.h:2399:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_ONESIDED_COMP at aomcx.h:2159:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_EXTERNAL_RATE_CONTROL at aomcx.h:2424:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_SUPERRES at aomcx.h:2198:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR at aomcx.h:2411:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET at aomcx.h:2267:1 in aomcx.h
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
#include <cstdlib>
#include <cstring>
#include <iostream>
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

static void init_codec_ctx(aom_codec_ctx_t &codec_ctx) {
    codec_ctx.name = "AV1";
    codec_ctx.iface = nullptr;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.config.enc = nullptr;
    codec_ctx.priv = nullptr;
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int max_drop = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR(&codec_ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR, max_drop);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_ONESIDED_COMP(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int enable = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_ENABLE_ONESIDED_COMP(&codec_ctx, AV1E_SET_ENABLE_ONESIDED_COMP, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_EXTERNAL_RATE_CONTROL(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_rc_funcs_t)) return;
    aom_rc_funcs_t rc_funcs;
    std::memcpy(&rc_funcs, Data, sizeof(aom_rc_funcs_t));
    aom_codec_control_typechecked_AV1E_SET_EXTERNAL_RATE_CONTROL(&codec_ctx, AV1E_SET_EXTERNAL_RATE_CONTROL, &rc_funcs);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_SUPERRES(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int enable = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_ENABLE_SUPERRES(&codec_ctx, AV1E_SET_ENABLE_SUPERRES, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int max_drop_ms = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR(&codec_ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR, max_drop_ms);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET(aom_codec_ctx_t &codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int enable = *reinterpret_cast<const int*>(Data);
    aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET(&codec_ctx, AV1E_SET_REDUCED_REFERENCE_SET, enable);
}

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    aom_codec_ctx_t codec_ctx;
    init_codec_ctx(codec_ctx);

    fuzz_aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_ONESIDED_COMP(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_EXTERNAL_RATE_CONTROL(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_SUPERRES(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET(codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    