// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT at aomcx.h:1979:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_V at aomcx.h:2102:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE at aomcx.h:2237:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_U at aomcx.h:2099:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_MAX at aomcx.h:2093:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP at aomcx.h:2378:1 in aomcx.h
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
#include <aomdx.h>
#include <aom.h>
#include <aom_codec.h>
#include <aom_external_partition.h>
#include <aom_decoder.h>
#include <aomcx.h>
#include <aom_integer.h>
#include <aom_frame_buffer.h>
#include <aom_image.h>
#include <aom_encoder.h>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    codec_ctx.name = "test_codec";

    // Prepare the integer value from the input data
    int value = 0;
    memcpy(&value, Data, sizeof(int));

    // Define control IDs for the functions
    const int AOME_SET_MAX_INTER_BITRATE_PCT = 0;
    const int AV1E_SET_QM_V = 1;
    const int AV1E_SET_DENOISE_BLOCK_SIZE = 2;
    const int AV1E_SET_QM_U = 3;
    const int AV1E_SET_QM_MAX = 4;
    const int AV1E_ENABLE_SB_QP_SWEEP = 5;

    // Fuzz aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT
    aom_codec_control_typechecked_AOME_SET_MAX_INTER_BITRATE_PCT(&codec_ctx, AOME_SET_MAX_INTER_BITRATE_PCT, static_cast<unsigned int>(value));

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_V
    aom_codec_control_typechecked_AV1E_SET_QM_V(&codec_ctx, AV1E_SET_QM_V, static_cast<unsigned int>(value));

    // Fuzz aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE
    aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(&codec_ctx, AV1E_SET_DENOISE_BLOCK_SIZE, static_cast<unsigned int>(value));

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_U
    aom_codec_control_typechecked_AV1E_SET_QM_U(&codec_ctx, AV1E_SET_QM_U, static_cast<unsigned int>(value));

    // Fuzz aom_codec_control_typechecked_AV1E_SET_QM_MAX
    aom_codec_control_typechecked_AV1E_SET_QM_MAX(&codec_ctx, AV1E_SET_QM_MAX, static_cast<unsigned int>(value));

    // Fuzz aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP
    aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP(&codec_ctx, AV1E_ENABLE_SB_QP_SWEEP, static_cast<unsigned int>(value));

    // Cleanup
    // Normally, you would call aom_codec_destroy(&codec_ctx) if the codec was initialized
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    