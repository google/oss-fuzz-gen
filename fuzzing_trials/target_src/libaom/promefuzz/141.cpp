// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT at aomdx.h:611:1 in aomdx.h
// aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE at aomcx.h:2396:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ at aomcx.h:2324:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_QM_MAX at aomcx.h:2093:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF at aomcx.h:2357:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_CQ_LEVEL at aomcx.h:1968:1 in aomcx.h
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
#include "aom.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(aom_codec_ctx_t) + sizeof(unsigned int)) {
        return 0; // Insufficient data
    }

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize codec context with dummy values
    codec_ctx.name = "dummy_codec";
    codec_ctx.iface = nullptr;
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.config.raw = nullptr;
    codec_ctx.priv = nullptr;

    // Use the first byte of data to decide which API function to call
    uint8_t choice = Data[0];
    Data++;
    Size--;

    unsigned int param = *reinterpret_cast<const unsigned int*>(Data);

    switch (choice % 6) {
        case 0: {
            // aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT
            aom_codec_control_typechecked_AOMD_SET_FRAME_SIZE_LIMIT(&codec_ctx, AOMD_SET_FRAME_SIZE_LIMIT, param);
            break;
        }
        case 1: {
            // aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE
            aom_codec_control_typechecked_AV1E_SET_SVC_FRAME_DROP_MODE(&codec_ctx, AV1E_SET_SVC_FRAME_DROP_MODE, param);
            break;
        }
        case 2: {
            // aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ
            aom_codec_control_typechecked_AV1E_SET_DV_COST_UPD_FREQ(&codec_ctx, AV1E_SET_DV_COST_UPD_FREQ, param);
            break;
        }
        case 3: {
            // aom_codec_control_typechecked_AV1E_SET_QM_MAX
            aom_codec_control_typechecked_AV1E_SET_QM_MAX(&codec_ctx, AV1E_SET_QM_MAX, param);
            break;
        }
        case 4: {
            // aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF
            aom_codec_control_typechecked_AV1E_SET_AUTO_INTRA_TOOLS_OFF(&codec_ctx, AV1E_SET_AUTO_INTRA_TOOLS_OFF, param);
            break;
        }
        case 5: {
            // aom_codec_control_typechecked_AOME_SET_CQ_LEVEL
            aom_codec_control_typechecked_AOME_SET_CQ_LEVEL(&codec_ctx, AOME_SET_CQ_LEVEL, param);
            break;
        }
        default:
            break;
    }

    // Cleanup if needed (depends on actual implementation and side-effects)
    // For this example, assume no cleanup is needed.

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

        LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    