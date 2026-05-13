// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
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
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_decoder.h"
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int value = *reinterpret_cast<const int*>(Data);
    aom_codec_ctx_t codec_ctx;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.iface = aom_codec_av1_cx();

    // Initialize codec context
    if (aom_codec_enc_init(&codec_ctx, codec_ctx.iface, nullptr, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_INTER_BITRATE_PCT, value);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_EXTERNAL_RATE_CONTROL
    aom_rc_funcs_t rc_funcs;
    rc_funcs.rc_type = static_cast<aom_rc_type_t>(value % 5); // Ensure valid enum value
    aom_codec_control(&codec_ctx, AV1E_SET_EXTERNAL_RATE_CONTROL, &rc_funcs);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_PAETH_INTRA
    int enable_paeth = value % 2; // Ensure boolean value
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_PAETH_INTRA, enable_paeth);

    // Fuzz aom_codec_control_typechecked_AOME_SET_TUNING
    aom_codec_control(&codec_ctx, AOME_SET_TUNING, value);

    // Fuzz aom_codec_control_typechecked_AOME_SET_VALIDATE_INPUT_HBD
    aom_codec_control(&codec_ctx, AOME_SET_VALIDATE_INPUT_HBD, enable_paeth);

    // Fuzz aom_codec_control_typechecked_AOME_SET_CQ_LEVEL
    aom_codec_control(&codec_ctx, AOME_SET_CQ_LEVEL, value);

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    