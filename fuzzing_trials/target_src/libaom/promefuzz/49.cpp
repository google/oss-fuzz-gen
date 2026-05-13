// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control_typechecked_AOMD_GET_ALTREF_PRESENT at aomdx.h:576:1 in aomdx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DIFF_WTD_COMP at aomcx.h:2168:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_TUNING at aomcx.h:1965:1 in aomcx.h
// aom_codec_control_typechecked_AOMD_GET_BASE_Q_IDX at aomdx.h:601:1 in aomdx.h
// aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT at aomcx.h:2258:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX at aomcx.h:2138:1 in aomcx.h
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
#include "aomdx.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res;

    // Initialize encoder
    res = aom_codec_enc_init(&codec, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Use the first int from the input data to decide control operations
    int control_id = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    // Prepare a dummy file if needed
    FILE *dummy_file = std::fopen("./dummy_file", "wb");
    if (dummy_file) {
        std::fwrite(Data, 1, Size, dummy_file);
        std::fclose(dummy_file);
    }

    // Dummy variables for control functions
    int int_param = 0;
    int *int_param_ptr = &int_param;
    int boolean_flag = 0;

    switch (control_id % 6) {
        case 0:
            aom_codec_control_typechecked_AOMD_GET_ALTREF_PRESENT(&codec, AOMD_GET_ALTREF_PRESENT, int_param_ptr);
            break;
        case 1:
            aom_codec_control_typechecked_AV1E_SET_ENABLE_DIFF_WTD_COMP(&codec, AV1E_SET_ENABLE_DIFF_WTD_COMP, boolean_flag);
            break;
        case 2:
            aom_codec_control_typechecked_AOME_SET_TUNING(&codec, AOME_SET_TUNING, int_param);
            break;
        case 3:
            aom_codec_control_typechecked_AOMD_GET_BASE_Q_IDX(&codec, AOMD_GET_BASE_Q_IDX, int_param_ptr);
            break;
        case 4:
            aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT(&codec, AV1E_SET_QUANT_B_ADAPT, boolean_flag);
            break;
        case 5:
            aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX(&codec, AV1E_SET_ENABLE_RECT_TX, boolean_flag);
            break;
        default:
            break;
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    