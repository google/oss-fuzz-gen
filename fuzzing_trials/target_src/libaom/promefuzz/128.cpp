// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
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
extern "C" {
#include <aom/aomcx.h>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>
}

#include <cstdint>
#include <cstring>
#include <iostream>

static void fuzz_aom_codec_control_typechecked_AV1E_SET_QM_U(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int qm_u = 0;
    std::memcpy(&qm_u, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_SET_QM_U, qm_u);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int block_size = 0;
    std::memcpy(&block_size, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_SET_DENOISE_BLOCK_SIZE, block_size);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_QM_MAX(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int qm_max = 0;
    std::memcpy(&qm_max, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_SET_QM_MAX, qm_max);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int enable = 0;
    std::memcpy(&enable, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int enable = 0;
    std::memcpy(&enable, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_ENABLE_SB_QP_SWEEP, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE(aom_codec_ctx_t *codec_ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int deltaq_mode = 0;
    std::memcpy(&deltaq_mode, Data, sizeof(unsigned int));
    aom_codec_control(codec_ctx, AV1E_SET_DELTAQ_MODE, deltaq_mode);
}

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec_ctx;
    std::memset(&codec_ctx, 0, sizeof(codec_ctx));

    fuzz_aom_codec_control_typechecked_AV1E_SET_QM_U(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_DENOISE_BLOCK_SIZE(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_QM_MAX(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_ADAPTIVE_SHARPNESS(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_ENABLE_SB_QP_SWEEP(&codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_DELTAQ_MODE(&codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    