// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
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
#include "aom_codec.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"

static void fuzz_codec_control(aom_codec_ctx_t *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;

    int param = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    aom_codec_control(ctx, AOMD_SET_FRAME_SIZE_LIMIT, param);
    aom_codec_control(ctx, AV1E_SET_MIN_CR, param);
    aom_codec_control(ctx, AV1E_SET_FP_MT_UNIT_TEST, param);
    aom_codec_control(ctx, AV1E_SET_FP_MT, param);
    aom_codec_control(ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_MS_CBR, param);
    aom_codec_control(ctx, AV1E_SET_BITRATE_ONE_PASS_CBR, param);
}

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t)) return 0;

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    
    codec_ctx.iface = aom_codec_av1_cx(); // Use a valid codec interface
    if (!codec_ctx.iface) return 0;

    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, codec_ctx.iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    fuzz_codec_control(&codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    