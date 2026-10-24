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
#include <cstdint>
#include <cstdlib>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        return 0;  // Exit if codec initialization fails
    }

    // Extract an integer from the input data
    int control_value = *reinterpret_cast<const int*>(Data);

    // Call each target function with the extracted integer
    aom_codec_control(&codec_ctx, AV1E_SET_DENOISE_NOISE_LEVEL, control_value);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, control_value % 2);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DNL_DENOISING, control_value % 2);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_TX_SIZE_SEARCH, control_value % 2);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_PALETTE, control_value % 2);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_1TO4_PARTITIONS, control_value % 2);

    // Destroy codec context
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

        LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    