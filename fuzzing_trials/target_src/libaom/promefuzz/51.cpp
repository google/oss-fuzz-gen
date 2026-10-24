// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_COMP at aomcx.h:2162:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DUAL_FILTER at aomcx.h:2150:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC at aomcx.h:2207:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_SMOOTH_INTRA at aomcx.h:2189:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_FILTER_INTRA at aomcx.h:2186:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ALLOW_WARPED_MOTION at aomcx.h:2183:1 in aomcx.h
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
#include <cstring>
#include <iostream>
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

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    // Prepare the codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize the codec interface
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    codec_ctx.iface = iface;

    // Extract control value from input data
    uint32_t control_value = *reinterpret_cast<const uint32_t *>(Data);
    bool enable = control_value % 2 == 0;

    // Call each target API function with the codec context and control value
    aom_codec_err_t err;

    err = aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_COMP(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_COMP, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set inter-intra comp: " << err << std::endl;
    }

    err = aom_codec_control_typechecked_AV1E_SET_ENABLE_DUAL_FILTER(&codec_ctx, AV1E_SET_ENABLE_DUAL_FILTER, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set dual filter: " << err << std::endl;
    }

    err = aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC(&codec_ctx, AV1E_SET_ENABLE_INTRABC, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set intra block copy: " << err << std::endl;
    }

    err = aom_codec_control_typechecked_AV1E_SET_ENABLE_SMOOTH_INTRA(&codec_ctx, AV1E_SET_ENABLE_SMOOTH_INTRA, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set smooth intra: " << err << std::endl;
    }

    err = aom_codec_control_typechecked_AV1E_SET_ENABLE_FILTER_INTRA(&codec_ctx, AV1E_SET_ENABLE_FILTER_INTRA, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set filter intra: " << err << std::endl;
    }

    err = aom_codec_control_typechecked_AV1E_SET_ALLOW_WARPED_MOTION(&codec_ctx, AV1E_SET_ALLOW_WARPED_MOTION, enable);
    if (err != AOM_CODEC_OK) {
        std::cerr << "Failed to set warped motion: " << err << std::endl;
    }

    // Cleanup if necessary
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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    