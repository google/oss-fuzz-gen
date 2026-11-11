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
#include <iostream>
#include <fstream>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aomcx.h>

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare the environment
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        return 0; // Early exit if codec initialization fails
    }

    // Step 2: Invoke the target functions with diverse inputs
    if (Size >= 1) {
        uint32_t freq = Data[0];
        aom_codec_control(&codec_ctx, AV1E_SET_MODE_COST_UPD_FREQ, freq);
    }
    if (Size >= 2) {
        uint32_t subsampling = Data[1];
        aom_codec_control(&codec_ctx, AV1E_SET_CHROMA_SUBSAMPLING_Y, subsampling);
    }
    if (Size >= 3) {
        uint32_t mv_freq = Data[2];
        aom_codec_control(&codec_ctx, AV1E_SET_MV_COST_UPD_FREQ, mv_freq);
    }
    if (Size >= 4) {
        uint32_t coeff_freq = Data[3];
        aom_codec_control(&codec_ctx, AV1E_SET_COEFF_COST_UPD_FREQ, coeff_freq);
    }
    if (Size >= 5) {
        uint32_t num_tg = Data[4];
        aom_codec_control(&codec_ctx, AV1E_SET_NUM_TG, num_tg);
    }
    if (Size >= 6) {
        uint32_t qm_y = Data[5];
        aom_codec_control(&codec_ctx, AV1E_SET_QM_Y, qm_y);
    }

    // Step 3: Cleanup
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

        LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    