// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstddef>
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

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    codec_ctx.name = "AV1 Codec";
    codec_ctx.iface = nullptr;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.priv = nullptr;

    // Prepare dummy file if needed
    std::ofstream dummy_file("./dummy_file");
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }

    // Extract boolean value from input data
    int enable_feature = Data[0] % 2;

    // Fuzz the target API functions
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DNL_DENOISING, enable_feature);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_COMP, enable_feature);
    aom_codec_control(&codec_ctx, AV1E_SET_ALLOW_REF_FRAME_MVS, enable_feature);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_AB_PARTITIONS, enable_feature);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_REF_FRAME_MVS, enable_feature);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_GLOBAL_MOTION, enable_feature);

    // Cleanup
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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    