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
#include <iostream>
#include <fstream>
#include "aom/aomdx.h"
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "/src/aom/aom/aom_external_partition.h"
#include "aom/aom_decoder.h"
#include "/src/aom/aom/aomcx.h"
#include "/src/aom/aom/aom_integer.h"
#include "/src/aom/aom/aom_frame_buffer.h"
#include "/src/aom/aom/aom_image.h"
#include "/src/aom/aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    if (aom_codec_enc_init(&codec_ctx, iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Use the input data to control the behavior of the codec
    int enable_interintra_wedge = Data[0] % 2;
    int number_spatial_layers = Data[1] % 4;
    int rtc_external_rc = Data[2] % 2;
    int timing_info_type = Data[3] % 3;
    aom_svc_ref_frame_comp_pred_t svc_ref_frame_comp_pred;
    svc_ref_frame_comp_pred.use_comp_pred[0] = Data[4] % 2;
    svc_ref_frame_comp_pred.use_comp_pred[1] = Data[5] % 2;
    svc_ref_frame_comp_pred.use_comp_pred[2] = Data[6] % 2;
    int intra_default_tx_only = Data[7] % 2;

    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_interintra_wedge);
    aom_codec_control(&codec_ctx, AOME_SET_NUMBER_SPATIAL_LAYERS, number_spatial_layers);
    aom_codec_control(&codec_ctx, AV1E_SET_RTC_EXTERNAL_RC, rtc_external_rc);
    aom_codec_control(&codec_ctx, AV1E_SET_TIMING_INFO_TYPE, timing_info_type);
    aom_codec_control(&codec_ctx, AV1E_SET_SVC_REF_FRAME_COMP_PRED, &svc_ref_frame_comp_pred);
    aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, intra_default_tx_only);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
