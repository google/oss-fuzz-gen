// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
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
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

static aom_codec_ctx_t initialize_codec() {
    aom_codec_ctx_t codec;
    aom_codec_iface_t* iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to get default codec config.\n");
        exit(EXIT_FAILURE);
    }
    if (aom_codec_enc_init(&codec, iface, &cfg, 0) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec.\n");
        exit(EXIT_FAILURE);
    }
    return codec;
}

static void cleanup_codec(aom_codec_ctx_t* codec) {
    if (aom_codec_destroy(codec) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to destroy codec.\n");
    }
}

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    aom_codec_ctx_t codec = initialize_codec();

    int value = 0;
    memcpy(&value, Data, sizeof(int));

    // Fuzz aom_codec_control_typechecked_AV1E_ENABLE_SB_MULTIPASS_UNIT_TEST
    if (aom_codec_control(&codec, AV1E_ENABLE_SB_MULTIPASS_UNIT_TEST, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_ENABLE_SB_MULTIPASS_UNIT_TEST.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_V
    if (aom_codec_control(&codec, AV1E_SET_QM_V, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_SET_QM_V.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_SKIP_POSTPROC_FILTERING
    if (aom_codec_control(&codec, AV1E_SET_SKIP_POSTPROC_FILTERING, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_SET_SKIP_POSTPROC_FILTERING.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
    if (aom_codec_control(&codec, AV1E_SET_DV_COST_UPD_FREQ, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_SET_DV_COST_UPD_FREQ.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_COEFF_COST_UPD_FREQ
    if (aom_codec_control(&codec, AV1E_SET_COEFF_COST_UPD_FREQ, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_SET_COEFF_COST_UPD_FREQ.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_Y
    if (aom_codec_control(&codec, AV1E_SET_QM_Y, value) != AOM_CODEC_OK) {
        fprintf(stderr, "Failed to control AV1E_SET_QM_Y.\n");
    }

    cleanup_codec(&codec);
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

        LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    