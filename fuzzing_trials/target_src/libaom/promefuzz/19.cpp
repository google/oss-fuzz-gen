// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_EXTERNAL_PARTITION at aomcx.h:2330:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_CFL_INTRA at aomcx.h:2195:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_MIN_PARTITION_SIZE at aomcx.h:2120:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_PALETTE at aomcx.h:2204:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ at aomcx.h:2153:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_AB_PARTITIONS at aomcx.h:2114:1 in aomcx.h
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
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize codec context with dummy data
    codec_ctx.err = (aom_codec_err_t)(Data[0] % 5);
    codec_ctx.init_flags = (aom_codec_flags_t)(Data[1] % 0x800000);
    codec_ctx.iface = nullptr;

    // Initialize external partition functions
    aom_ext_part_funcs_t ext_part_funcs;
    memset(&ext_part_funcs, 0, sizeof(ext_part_funcs));
    ext_part_funcs.decision_mode = (aom_ext_part_decision_mode_t)(Data[2] % 2);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_EXTERNAL_PARTITION
    aom_codec_err_t res1 = aom_codec_control_typechecked_AV1E_SET_EXTERNAL_PARTITION(
        &codec_ctx, AV1E_SET_EXTERNAL_PARTITION, &ext_part_funcs);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_CFL_INTRA
    int enable_cfl = Data[3] % 2;
    aom_codec_err_t res2 = aom_codec_control_typechecked_AV1E_SET_ENABLE_CFL_INTRA(
        &codec_ctx, AV1E_SET_ENABLE_CFL_INTRA, enable_cfl);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_MIN_PARTITION_SIZE
    int min_partition_size = Data[4] % 128;
    aom_codec_err_t res3 = aom_codec_control_typechecked_AV1E_SET_MIN_PARTITION_SIZE(
        &codec_ctx, AV1E_SET_MIN_PARTITION_SIZE, min_partition_size);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_PALETTE
    int enable_palette = Data[5] % 2;
    aom_codec_err_t res4 = aom_codec_control_typechecked_AV1E_SET_ENABLE_PALETTE(
        &codec_ctx, AV1E_SET_ENABLE_PALETTE, enable_palette);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ
    int enable_chroma_deltaq = Data[6] % 2;
    aom_codec_err_t res5 = aom_codec_control_typechecked_AV1E_SET_ENABLE_CHROMA_DELTAQ(
        &codec_ctx, AV1E_SET_ENABLE_CHROMA_DELTAQ, enable_chroma_deltaq);

    // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_AB_PARTITIONS
    int enable_ab_partitions = Data[7] % 2;
    aom_codec_err_t res6 = aom_codec_control_typechecked_AV1E_SET_ENABLE_AB_PARTITIONS(
        &codec_ctx, AV1E_SET_ENABLE_AB_PARTITIONS, enable_ab_partitions);

    // Handle errors (if any)
    if (res1 != AOM_CODEC_OK || res2 != AOM_CODEC_OK || res3 != AOM_CODEC_OK ||
        res4 != AOM_CODEC_OK || res5 != AOM_CODEC_OK || res6 != AOM_CODEC_OK) {
        // An error occurred, but for fuzzing purposes, we don't need to do anything
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    