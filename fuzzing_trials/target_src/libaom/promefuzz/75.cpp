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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "aom.h"
#include "aomcx.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    int param_value = 0;
    memcpy(&param_value, Data, sizeof(int));
    const uint8_t *remaining_data = Data + sizeof(int);
    size_t remaining_size = Size - sizeof(int);

    // Initialize codec context
    if (aom_codec_enc_init(&codec_ctx, aom_codec_av1_cx(), nullptr, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz different control functions with the extracted parameter
    aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, param_value);
    aom_codec_control(&codec_ctx, AV1E_SET_MODE_COST_UPD_FREQ, param_value);
    aom_codec_control(&codec_ctx, AV1E_SET_QM_MIN, param_value);
    aom_codec_control(&codec_ctx, AV1E_SET_MIN_CR, param_value);
    aom_codec_control(&codec_ctx, AV1E_SET_QM_Y, param_value);
    aom_codec_control(&codec_ctx, AV1E_SET_MTU, param_value);

    // Clean up codec context
    if (aom_codec_destroy(&codec_ctx) != AOM_CODEC_OK) {
        return 0;
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

        LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    