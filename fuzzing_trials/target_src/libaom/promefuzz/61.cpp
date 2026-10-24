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
#include <iostream>
#include <fstream>
#include <cstdint>
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

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Create a dummy file if necessary
    std::ofstream dummy_file("./dummy_file", std::ios::binary);
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }

    // Define control IDs
    int ctrl_id_dnl_denoising = AV1E_SET_ENABLE_DNL_DENOISING;
    int ctrl_id_quantizer_one_pass = AV1E_SET_QUANTIZER_ONE_PASS;
    int ctrl_id_timing_info_type = AV1E_SET_TIMING_INFO_TYPE;
    int ctrl_id_tx_size_search = AV1E_SET_ENABLE_TX_SIZE_SEARCH;
    int ctrl_id_reduced_reference_set = AV1E_SET_REDUCED_REFERENCE_SET;
    int ctrl_id_intra_default_tx_only = AV1E_SET_INTRA_DEFAULT_TX_ONLY;

    // Call aom_codec_control_typechecked_AV1E_SET_ENABLE_DNL_DENOISING
    int enable_dnl_denoising = Data[0] % 2; // Boolean value
    aom_codec_control(&codec_ctx, ctrl_id_dnl_denoising, enable_dnl_denoising);

    // Call aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS
    int quantizer_value = Data[0] % 256; // Quantizer value
    aom_codec_control(&codec_ctx, ctrl_id_quantizer_one_pass, quantizer_value);

    // Call aom_codec_control_typechecked_AV1E_SET_TIMING_INFO_TYPE
    int timing_info_type = Data[0] % 3; // Timing info type
    aom_codec_control(&codec_ctx, ctrl_id_timing_info_type, timing_info_type);

    // Call aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH
    int enable_tx_size_search = Data[0] % 2; // Boolean value
    aom_codec_control(&codec_ctx, ctrl_id_tx_size_search, enable_tx_size_search);

    // Call aom_codec_control_typechecked_AV1E_SET_REDUCED_REFERENCE_SET
    int reduced_reference_set = Data[0] % 2; // Boolean value
    aom_codec_control(&codec_ctx, ctrl_id_reduced_reference_set, reduced_reference_set);

    // Call aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY
    int intra_default_tx_only = Data[0] % 2; // Boolean value
    aom_codec_control(&codec_ctx, ctrl_id_intra_default_tx_only, intra_default_tx_only);

    // Destroy codec context
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

        LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    