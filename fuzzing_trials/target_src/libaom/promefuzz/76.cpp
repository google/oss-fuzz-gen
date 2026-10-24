// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR at aomcx.h:2399:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC at aomcx.h:2405:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET at aomcx.h:2267:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY at aomcx.h:2255:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY at aomcx.h:2252:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SVC_LAYER_ID at aomcx.h:2285:1 in aomcx.h
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
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_decoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    int param = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR
    if (Size >= sizeof(int)) {
        int max_consec_frame_drop = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);

        aom_codec_control_typechecked_AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR(&codec_ctx, AV1E_SET_MAX_CONSEC_FRAME_DROP_CBR, max_consec_frame_drop);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC
    if (Size >= sizeof(int)) {
        int high_motion_content = 0;
        aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC(&codec_ctx, AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC, &high_motion_content);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET
    if (Size >= sizeof(int)) {
        int reduced_reference_set = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);

        aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET(&codec_ctx, AV1E_SET_REDUCED_REFERENCE_SET, reduced_reference_set);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY
    if (Size >= sizeof(int)) {
        int intra_default_tx_only = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);

        aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(&codec_ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, intra_default_tx_only);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY
    if (Size >= sizeof(int)) {
        int inter_dct_only = *reinterpret_cast<const int*>(Data);
        Data += sizeof(int);
        Size -= sizeof(int);

        aom_codec_control_typechecked_AV1E_SET_INTER_DCT_ONLY(&codec_ctx, AV1E_SET_INTER_DCT_ONLY, inter_dct_only);
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SVC_LAYER_ID
    if (Size >= sizeof(aom_svc_layer_id_t)) {
        aom_svc_layer_id_t svc_layer_id;
        memcpy(&svc_layer_id, Data, sizeof(aom_svc_layer_id_t));
        Data += sizeof(aom_svc_layer_id_t);
        Size -= sizeof(aom_svc_layer_id_t);

        aom_codec_control_typechecked_AV1E_SET_SVC_LAYER_ID(&codec_ctx, AV1E_SET_SVC_LAYER_ID, &svc_layer_id);
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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    