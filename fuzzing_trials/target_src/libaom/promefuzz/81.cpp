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
#include "aom/aomdx.h"
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_external_partition.h"
#include "aom/aom_decoder.h"
#include "aom/aomcx.h"
#include "aom/aom_integer.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_image.h"
#include "aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t)) {
        return 0;
    }

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz aom_codec_control_typechecked_AOMD_GET_SCREEN_CONTENT_TOOLS_INFO
    aom_screen_content_tools_info screen_content_info;
    res = aom_codec_control(&codec, AOMD_GET_SCREEN_CONTENT_TOOLS_INFO, &screen_content_info);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_NUM_OPERATING_POINTS
    int num_operating_points;
    res = aom_codec_control(&codec, AV1E_GET_NUM_OPERATING_POINTS, &num_operating_points);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS
    int enable_1to4_partitions = Data[0] % 2; // Random enable/disable
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_1TO4_PARTITIONS, enable_1to4_partitions);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QUANT_B_ADAPT
    int quant_b_adapt = Data[0] % 256; // Random quantization parameter
    res = aom_codec_control(&codec, AV1E_SET_QUANT_B_ADAPT, quant_b_adapt);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC
    int high_motion_content_screen_rtc;
    res = aom_codec_control(&codec, AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC, &high_motion_content_screen_rtc);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
    }

    // Fuzz aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH
    int luma_cdef_strength;
    res = aom_codec_control(&codec, AV1E_GET_LUMA_CDEF_STRENGTH, &luma_cdef_strength);
    if (res != AOM_CODEC_OK) {
        // Handle error or log
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

        LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    