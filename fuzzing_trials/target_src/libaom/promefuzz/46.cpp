// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET at aomcx.h:2246:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_DIRECTIONAL_INTRA at aomcx.h:2333:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ALLOW_REF_FRAME_MVS at aomcx.h:2147:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS at aomcx.h:2111:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_FILTER_INTRA at aomcx.h:2186:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_FLIP_IDTX at aomcx.h:2135:1 in aomcx.h
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
extern "C" {
#include <aom/aomdx.h>
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_encoder.h>
}

#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Extract control value from input data
    int control_value = 0;
    memcpy(&control_value, Data, sizeof(int));

    // Try different API functions with the extracted control value
    aom_codec_err_t res;

    // aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET
    res = aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_REDUCED_TX_TYPE_SET: " << res << std::endl;
    }

    // aom_codec_control_typechecked_AV1E_SET_ENABLE_DIRECTIONAL_INTRA
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_DIRECTIONAL_INTRA(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ENABLE_DIRECTIONAL_INTRA: " << res << std::endl;
    }

    // aom_codec_control_typechecked_AV1E_SET_ALLOW_REF_FRAME_MVS
    res = aom_codec_control_typechecked_AV1E_SET_ALLOW_REF_FRAME_MVS(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ALLOW_REF_FRAME_MVS: " << res << std::endl;
    }

    // aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ENABLE_RECT_PARTITIONS: " << res << std::endl;
    }

    // aom_codec_control_typechecked_AV1E_SET_ENABLE_FILTER_INTRA
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_FILTER_INTRA(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ENABLE_FILTER_INTRA: " << res << std::endl;
    }

    // aom_codec_control_typechecked_AV1E_SET_ENABLE_FLIP_IDTX
    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_FLIP_IDTX(&codec_ctx, 0, control_value);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error in AV1E_SET_ENABLE_FLIP_IDTX: " << res << std::endl;
    }

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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    