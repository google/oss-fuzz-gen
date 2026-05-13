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
#include <aom/aomdx.h>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0;

    // Prepare codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.iface = aom_codec_av1_cx();
    if (!codec_ctx.iface) return 0;

    // Initialize codec for encoding
    if (aom_codec_enc_init(&codec_ctx, codec_ctx.iface, nullptr, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Extract values from input data
    const bool enable_dist_wtd_comp = Data[0] % 2;
    const bool enable_tx64 = Data[1] % 2;
    const bool enable_masked_comp = Data[2] % 2;
    const bool enable_onesided_comp = Data[3] % 2;
    const int min_partition_size = Data[4] % 128; // Arbitrary limit
    const bool enable_dual_filter = Data[5] % 2;

    // Fuzz target functions
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DIST_WTD_COMP, enable_dist_wtd_comp);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_TX64, enable_tx64);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_MASKED_COMP, enable_masked_comp);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_ONESIDED_COMP, enable_onesided_comp);
    aom_codec_control(&codec_ctx, AV1E_SET_MIN_PARTITION_SIZE, min_partition_size);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DUAL_FILTER, enable_dual_filter);

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

        LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    