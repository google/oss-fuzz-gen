// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
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
extern "C" {
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_external_partition.h>
}

#include <cstddef>
#include <cstdint>
#include <cstring>

static void fuzz_codec_control(aom_codec_ctx_t *codec, const uint8_t *data, size_t size) {
    if (size < sizeof(int) + 1) return;
    
    int control_id = data[0] % 6;
    int param = 0;
    memcpy(&param, data + 1, sizeof(int));

    switch (control_id) {
        case 0:
            aom_codec_control(codec, AV1E_SET_ENABLE_INTERINTRA_COMP, param);
            break;
        case 1:
            aom_codec_control(codec, AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC, &param);
            break;
        case 2:
            aom_codec_control(codec, AV1E_SET_REDUCED_REFERENCE_SET, param);
            break;
        case 3:
            aom_codec_control(codec, AV1E_SET_INTRA_DEFAULT_TX_ONLY, param);
            break;
        case 4:
            aom_codec_control(codec, AV1E_SET_INTER_DCT_ONLY, param);
            break;
        case 5:
            aom_svc_layer_id_t layer_id;
            layer_id.spatial_layer_id = param;
            aom_codec_control(codec, AV1E_SET_SVC_LAYER_ID, &layer_id);
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    aom_codec_err_t res = aom_codec_enc_config_default(iface, &cfg, 0);
    
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    res = aom_codec_enc_init(&codec, iface, &cfg, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    fuzz_codec_control(&codec, Data, Size);

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

        LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    