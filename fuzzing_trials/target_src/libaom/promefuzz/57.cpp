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
#include <iostream>
#include <fstream>
#include <cstring>
#include "aomdx.h"
#include "aom.h"
#include "aom_codec.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aomcx.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_encoder.h"

static void initialize_codec_context(aom_codec_ctx_t &ctx) {
    ctx.name = "AV1 Codec";
    ctx.iface = nullptr;
    ctx.err = AOM_CODEC_OK;
    ctx.init_flags = 0;
    ctx.config.enc = nullptr;
    ctx.priv = nullptr;
}

static void fuzz_partition_info_path(aom_codec_ctx_t &ctx, const uint8_t *Data, size_t Size) {
    std::ofstream outfile("./dummy_file", std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(Data), Size);
    outfile.close();

    const char *path = "./dummy_file";
    aom_codec_control(&ctx, AV1E_SET_PARTITION_INFO_PATH, path);
}

static void fuzz_quantizer_one_pass(aom_codec_ctx_t &ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int quantizer = *reinterpret_cast<const int*>(Data);
    aom_codec_control(&ctx, AV1E_SET_QUANTIZER_ONE_PASS, quantizer);
}

static void fuzz_target_seq_level_idx(aom_codec_ctx_t &ctx) {
    int level_idx;
    aom_codec_control(&ctx, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &level_idx);
}

static void fuzz_film_grain_table(aom_codec_ctx_t &ctx, const uint8_t *Data, size_t Size) {
    const char *grain_table = reinterpret_cast<const char*>(Data);
    aom_codec_control(&ctx, AV1E_SET_FILM_GRAIN_TABLE, grain_table);
}

static void fuzz_vmaf_model_path(aom_codec_ctx_t &ctx, const uint8_t *Data, size_t Size) {
    std::ofstream outfile("./dummy_file", std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(Data), Size);
    outfile.close();

    const char *path = "./dummy_file";
    aom_codec_control(&ctx, AV1E_SET_VMAF_MODEL_PATH, path);
}

static void fuzz_inter_dct_only(aom_codec_ctx_t &ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int enable = *reinterpret_cast<const int*>(Data);
    aom_codec_control(&ctx, AV1E_SET_INTER_DCT_ONLY, enable);
}

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec_ctx;
    initialize_codec_context(codec_ctx);

    fuzz_partition_info_path(codec_ctx, Data, Size);
    fuzz_quantizer_one_pass(codec_ctx, Data, Size);
    fuzz_target_seq_level_idx(codec_ctx);
    fuzz_film_grain_table(codec_ctx, Data, Size);
    fuzz_vmaf_model_path(codec_ctx, Data, Size);
    fuzz_inter_dct_only(codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    