// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_decoder.h"
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_124(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 6) {
        return 0; // Not enough data to extract parameters
    }

    int enable_smooth_interintra = Data[0] % 2;
    int enable_interintra_wedge = Data[1] % 2;
    int enable_cfl_intra = Data[2] % 2;
    int enable_dnl_denoising = Data[3] % 2;
    int enable_global_motion = Data[4] % 2;
    int enable_ab_partitions = Data[5] % 2;

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) {
        return 0; // Failed to get codec interface
    }

    codec_ctx.iface = iface;

    try {
        aom_codec_err_t res;

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_SMOOTH_INTERINTRA, enable_smooth_interintra);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set smooth interintra");

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_interintra_wedge);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set interintra wedge");

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_CFL_INTRA, enable_cfl_intra);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set CFL intra");

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DNL_DENOISING, enable_dnl_denoising);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set DNL denoising");

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_GLOBAL_MOTION, enable_global_motion);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set global motion");

        res = aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_AB_PARTITIONS, enable_ab_partitions);
        if (res != AOM_CODEC_OK) throw std::runtime_error("Failed to set AB partitions");

    } catch (const std::exception &e) {
        fprintf(stderr, "Exception: %s\n", e.what());
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

        LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    