// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER at aomcx.h:2126:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_CONFIG at aomcx.h:2295:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC at aomcx.h:2360:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH at aomcx.h:2336:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS at aomcx.h:2117:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH at aomcx.h:2390:1 in aomcx.h
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

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2; // Use the first byte to decide enable/disable
    aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER(codec, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_CONFIG(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_svc_ref_frame_config_t)) return;
    aom_svc_ref_frame_config_t config;
    memcpy(&config, Data, sizeof(config));
    aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_CONFIG(codec, AV1E_SET_SVC_REF_FRAME_CONFIG, &config);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int external_rc = Data[0] % 2; // Use the first byte to decide enable/disable
    aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(codec, AV1E_SET_RTC_EXTERNAL_RC, external_rc);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2; // Use the first byte to decide enable/disable
    aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH(codec, AV1E_SET_ENABLE_TX_SIZE_SEARCH, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    int enable = Data[0] % 2; // Use the first byte to decide enable/disable
    aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS(codec, AV1E_SET_ENABLE_1TO4_PARTITIONS, enable);
}

static void fuzz_aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(aom_codec_ctx_t *codec) {
    int strength;
    aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(codec, AV1E_GET_LUMA_CDEF_STRENGTH, &strength);
}

extern "C" int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    // Initialize codec context here if necessary
    // ...

    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRA_EDGE_FILTER(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_SVC_REF_FRAME_CONFIG(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_1TO4_PARTITIONS(&codec, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_GET_LUMA_CDEF_STRENGTH(&codec);

    // Perform cleanup if necessary
    // ...

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

        LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    