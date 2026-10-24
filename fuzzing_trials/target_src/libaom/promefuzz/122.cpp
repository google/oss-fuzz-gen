// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
#include <iostream>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include "aom.h"
#include "aom_codec.h"
#include "aom_encoder.h"
#include "aomcx.h"

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + 1) {
        return 0;
    }

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    codec.iface = aom_codec_av1_cx();

    int frequency_value;
    memcpy(&frequency_value, Data, sizeof(int));

    aom_codec_err_t res;

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MODE_COST_UPD_FREQ
    res = aom_codec_control(&codec, AV1E_SET_MODE_COST_UPD_FREQ, frequency_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_MODE_COST_UPD_FREQ: " << res << std::endl;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER
    int enable_edge_filter = Data[sizeof(int)] % 2;
    res = aom_codec_control(&codec, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, enable_edge_filter);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ENABLE_INTRA_EDGE_FILTER: " << res << std::endl;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
    res = aom_codec_control(&codec, AV1E_SET_DV_COST_UPD_FREQ, frequency_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_DV_COST_UPD_FREQ: " << res << std::endl;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MV_COST_UPD_FREQ
    res = aom_codec_control(&codec, AV1E_SET_MV_COST_UPD_FREQ, frequency_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_MV_COST_UPD_FREQ: " << res << std::endl;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_COEFF_COST_UPD_FREQ
    res = aom_codec_control(&codec, AV1E_SET_COEFF_COST_UPD_FREQ, frequency_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_COEFF_COST_UPD_FREQ: " << res << std::endl;
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP
    int complexity_value = frequency_value % 100; // Arbitrary complexity value
    res = aom_codec_control(&codec, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, complexity_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP: " << res << std::endl;
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

        LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    