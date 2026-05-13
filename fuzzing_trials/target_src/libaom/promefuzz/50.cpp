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

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Assuming codec interface is available
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) return 0;

    codec_ctx.iface = iface;

    // Extract integer values from the input data for fuzzing
    int max_consec_frame_drop_cbr = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    int denoise_noise_level = 0;
    if (Size >= sizeof(int)) {
        denoise_noise_level = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    int enable_interintra_wedge = 0;
    if (Size >= sizeof(int)) {
        enable_interintra_wedge = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    int enable_directional_intra = 0;
    if (Size >= sizeof(int)) {
        enable_directional_intra = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    int postencode_drop_rtc = 0;
    if (Size >= sizeof(int)) {
        postencode_drop_rtc = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    int enable_rect_tx = 0;
    if (Size >= sizeof(int)) {
        enable_rect_tx = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Fuzz the target functions with extracted values
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR, max_consec_frame_drop_cbr);
    aom_codec_control(&codec_ctx, AV1E_SET_DENOISE_NOISE_LEVEL, denoise_noise_level);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_interintra_wedge);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DIRECTIONAL_INTRA, enable_directional_intra);
    aom_codec_control(&codec_ctx, AV1E_SET_POSTENCODE_DROP_RTC, postencode_drop_rtc);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, enable_rect_tx);

    // Clean up codec context
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    