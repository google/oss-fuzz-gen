// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
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
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"
#include "aomdx.h"

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    aom_codec_err_t res;

    // Initialize codec
    res = aom_codec_enc_config_default(iface, &cfg, 0);
    if (res != AOM_CODEC_OK) return 0;

    res = aom_codec_enc_init(&codec, iface, &cfg, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Prepare a quantizer value from input data
    int quantizer = Data[0] % 64; // Limit quantizer to a valid range
    res = aom_codec_control(&codec, AV1E_SET_QUANTIZER_ONE_PASS, quantizer);
    if (res != AOM_CODEC_OK) goto cleanup;

    // Prepare buffer for GOP info
    aom_gop_info_t gop_info;
    res = aom_codec_control(&codec, AV1E_GET_GOP_INFO, &gop_info);
    if (res != AOM_CODEC_OK) goto cleanup;

    // Prepare buffer for base Q index
    int base_q_idx;
    res = aom_codec_control(&codec, AOMD_GET_BASE_Q_IDX, &base_q_idx);
    if (res != AOM_CODEC_OK) goto cleanup;

    // Prepare buffer for target sequence level index
    int target_seq_level_idx;
    res = aom_codec_control(&codec, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &target_seq_level_idx);
    if (res != AOM_CODEC_OK) goto cleanup;

    // Prepare buffer for loop filter level
    int loop_filter_level;
    res = aom_codec_control(&codec, AOME_GET_LOOPFILTER_LEVEL, &loop_filter_level);
    if (res != AOM_CODEC_OK) goto cleanup;

    // Prepare buffer for baseline GF interval
    int baseline_gf_interval;
    res = aom_codec_control(&codec, AV1E_GET_BASELINE_GF_INTERVAL, &baseline_gf_interval);
    if (res != AOM_CODEC_OK) goto cleanup;

cleanup:
    aom_codec_destroy(&codec);
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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    