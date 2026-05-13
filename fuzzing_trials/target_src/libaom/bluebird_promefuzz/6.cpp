#include <string.h>
#include <sys/stat.h>
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
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "/src/aom/aom/aomcx.h"
#include "aom/aom_decoder.h"
#include "/src/aom/aom/aom_encoder.h"
#include "/src/aom/aom/aom_external_partition.h"
#include "/src/aom/aom/aom_frame_buffer.h"
#include "/src/aom/aom/aom_image.h"
#include "/src/aom/aom/aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + sizeof(aom_svc_params_t)) {
        return 0;
    }

    // Initialize codec context with default encoder interface
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    if (aom_codec_enc_init(&codec_ctx, iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Prepare SVC parameters
    aom_svc_params_t svc_params;
    memcpy(&svc_params, Data, sizeof(aom_svc_params_t));
    Data += sizeof(aom_svc_params_t);
    Size -= sizeof(aom_svc_params_t);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR
    if (Size >= sizeof(int)) {
        int max_consec_frame_drop_cbr = *reinterpret_cast<const int*>(Data);
        aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR(
            &codec_ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR, max_consec_frame_drop_cbr);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS
    if (Size >= sizeof(int)) {
        int quantizer_one_pass = *reinterpret_cast<const int*>(Data);
        aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS(
            &codec_ctx, AV1E_SET_QUANTIZER_ONE_PASS, quantizer_one_pass);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SVC_PARAMS
    aom_codec_control_typechecked_AV1E_SET_SVC_PARAMS(
        &codec_ctx, AV1E_SET_SVC_PARAMS, &svc_params);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE
    if (Size >= sizeof(int)) {
        int timing_info_type = *reinterpret_cast<const int*>(Data);
        aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE(
            &codec_ctx, AV1E_SET_TIMING_INFO_TYPE, timing_info_type);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_POSTENCODE_DROP_RTC
    if (Size >= sizeof(int)) {
        int postencode_drop_rtc = *reinterpret_cast<const int*>(Data);
        aom_codec_control_typechecked_AV1E_SET_POSTENCODE_DROP_RTC(
            &codec_ctx, AV1E_SET_POSTENCODE_DROP_RTC, postencode_drop_rtc);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY
    if (Size >= sizeof(int)) {
        int inter_dct_only = *reinterpret_cast<const int*>(Data);
        aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY(
            &codec_ctx, AV1E_SET_INTER_DCT_ONLY, inter_dct_only);
        Data += sizeof(int);
        Size -= sizeof(int);
    }

    // Cleanup codec context
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
