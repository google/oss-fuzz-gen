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

static void initialize_codec(aom_codec_ctx_t &codec, aom_codec_iface_t *iface) {
    // Initialize the codec with a dummy interface
    aom_codec_dec_cfg_t cfg = {0};
    aom_codec_dec_init(&codec, iface, &cfg, 0);
}

static void cleanup_codec(aom_codec_ctx_t &codec) {
    aom_codec_destroy(&codec);
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0; // Ensure enough data for operations

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_dx(); // Get the AV1 decoder interface

    initialize_codec(codec, iface);

    // Use the first byte to decide which function to call
    int choice = Data[0] % 6;

    switch (choice) {
        case 0: {
            int alt_ref_present = 0;
            aom_codec_control(&codec, AOMD_GET_ALTREF_PRESENT, &alt_ref_present);
            break;
        }
        case 1: {
            if (Size < sizeof(int) + 1) break;
            int spatial_layers = static_cast<int>(Data[1]);
            aom_codec_control(&codec, AOME_SET_NUMBER_SPATIAL_LAYERS, &spatial_layers);
            break;
        }
        case 2: {
            if (Size < sizeof(int) + 1) break;
            int quantizer = static_cast<int>(Data[1]);
            aom_codec_control(&codec, AV1E_SET_QUANTIZER_ONE_PASS, &quantizer);
            break;
        }
        case 3: {
            if (Size < sizeof(int) + 1) break;
            int tuning = static_cast<int>(Data[1]);
            aom_codec_control(&codec, AOME_SET_TUNING, &tuning);
            break;
        }
        case 4: {
            int base_q_idx = 0;
            aom_codec_control(&codec, AOMD_GET_BASE_Q_IDX, &base_q_idx);
            break;
        }
        case 5: {
            int target_seq_level_idx = 0;
            aom_codec_control(&codec, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &target_seq_level_idx);
            break;
        }
        default:
            break;
    }

    cleanup_codec(codec);
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
