// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_COMP at aomcx.h:2162:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_MAX_PARTITION_SIZE at aomcx.h:2123:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE at aomcx.h:2417:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS at aomcx.h:2111:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY at aomcx.h:2249:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC at aomcx.h:2405:1 in aomcx.h
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
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aomcx.h"
#include "aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + sizeof(int)) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Assume first few bytes are for codec context initialization
    memcpy(&codec_ctx, Data, sizeof(aom_codec_ctx_t));
    Data += sizeof(aom_codec_ctx_t);
    Size -= sizeof(aom_codec_ctx_t);

    // Use the remaining data as parameters for the functions
    int param = 0;
    if (Size >= sizeof(int)) {
        memcpy(&param, Data, sizeof(int));
    }

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_COMP
    aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_COMP(&codec_ctx, 0, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_MAX_PARTITION_SIZE
    aom_codec_control_typechecked_AV1E_SET_MAX_PARTITION_SIZE(&codec_ctx, 0, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE
    aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE(&codec_ctx, 0, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS
    aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS(&codec_ctx, 0, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY
    aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY(&codec_ctx, 0, param);

    // Fuzzing aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC
    aom_codec_control_typechecked_AV1E_GET_HIGH_MOTION_CONTENT_SCREEN_RTC(&codec_ctx, 0, &param);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    