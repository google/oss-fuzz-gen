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
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void fuzz_codec_control(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Randomly choose a function to call
    int choice = Data[0] % 6;
    Data++;
    Size--;

    if (Size < 1) return; // Ensure there is at least 1 byte left for further operations

    switch (choice) {
        case 0: {
            int num_operating_points;
            aom_codec_control(codec, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);
            break;
        }
        case 1: {
            int enable_warped_motion = Data[0] % 2;
            aom_codec_control(codec, AV1E_SET_ENABLE_WARPED_MOTION, enable_warped_motion);
            break;
        }
        case 2: {
            int enable_tx_size_search = Data[0] % 2;
            aom_codec_control(codec, AV1E_SET_ENABLE_TX_SIZE_SEARCH, enable_tx_size_search);
            break;
        }
        case 3: {
            int intra_default_tx_only = Data[0] % 2;
            aom_codec_control(codec, AV1E_SET_INTRA_DEFAULT_TX_ONLY, intra_default_tx_only);
            break;
        }
        case 4: {
            int baseline_gf_interval;
            aom_codec_control(codec, AV1E_GET_BASELINE_GF_INTERVAL, &baseline_gf_interval);
            break;
        }
        case 5: {
            int luma_cdef_strength[64]; // Adjusted to match or exceed CDEF_MAX_STRENGTHS
            aom_codec_control(codec, AV1E_GET_LUMA_CDEF_STRENGTH, luma_cdef_strength);
            break;
        }
        default:
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    
    if (aom_codec_enc_config_default(iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    if (aom_codec_enc_init(&codec, iface, &cfg, 0) != AOM_CODEC_OK) {
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

        LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    