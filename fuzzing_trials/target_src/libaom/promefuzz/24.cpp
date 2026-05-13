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
#include <iostream>
#include <fstream>
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

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 6) {
        return 0;
    }

    // Prepare codec context
    aom_codec_ctx_t codec_ctx;
    codec_ctx.name = "AV1 Codec";
    codec_ctx.iface = aom_codec_av1_cx();
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.priv = nullptr;

    // Extract boolean values from input data
    int enable_intra_edge_filter = Data[0] % 2;
    int enable_dnl_denoising = Data[1] % 2;
    int enable_interintra_comp = Data[2] % 2;
    int enable_paeth_intra = Data[3] % 2;
    int enable_intrabc = Data[4] % 2;
    int enable_angle_delta = Data[5] % 2;

    // Invoke target functions with diverse inputs
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, enable_intra_edge_filter);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DNL_DENOISING, enable_dnl_denoising);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_COMP, enable_interintra_comp);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_PAETH_INTRA, enable_paeth_intra);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTRABC, enable_intrabc);
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_ANGLE_DELTA, enable_angle_delta);

    // Clean up and handle any errors
    if (codec_ctx.err != AOM_CODEC_OK) {
        std::cerr << "Codec error: " << codec_ctx.err << std::endl;
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    