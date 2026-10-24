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
#include <cstring>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>
#include <aom/aomcx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_external_partition.h>

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0; // Ensure we have enough data for all parameters

    aom_codec_ctx_t codec_ctx = {0};
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);

    if (res != AOM_CODEC_OK) {
        return 0; // Initialization failed, exit early
    }

    // Extract values from the input data
    uint32_t mode_cost_upd_freq = Data[0];
    uint32_t chroma_subsampling_y = Data[1];
    uint32_t dv_cost_upd_freq = Data[2];
    uint32_t coeff_cost_upd_freq = Data[3];
    uint32_t mv_cost_upd_freq = Data[4];
    uint32_t num_tg = Data[5];

    // Control IDs for the API functions
    int ctrl_mode_cost_upd_freq = AV1E_SET_MODE_COST_UPD_FREQ;
    int ctrl_chroma_subsampling_y = AV1E_SET_CHROMA_SUBSAMPLING_Y;
    int ctrl_dv_cost_upd_freq = AV1E_SET_DV_COST_UPD_FREQ;
    int ctrl_coeff_cost_upd_freq = AV1E_SET_COEFF_COST_UPD_FREQ;
    int ctrl_mv_cost_upd_freq = AV1E_SET_MV_COST_UPD_FREQ;
    int ctrl_num_tg = AV1E_SET_NUM_TG;

    // Fuzz different API functions with extracted values
    aom_codec_control(&codec_ctx, ctrl_mode_cost_upd_freq, mode_cost_upd_freq);
    aom_codec_control(&codec_ctx, ctrl_chroma_subsampling_y, chroma_subsampling_y);
    aom_codec_control(&codec_ctx, ctrl_dv_cost_upd_freq, dv_cost_upd_freq);
    aom_codec_control(&codec_ctx, ctrl_coeff_cost_upd_freq, coeff_cost_upd_freq);
    aom_codec_control(&codec_ctx, ctrl_mv_cost_upd_freq, mv_cost_upd_freq);
    aom_codec_control(&codec_ctx, ctrl_num_tg, num_tg);

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

        LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    