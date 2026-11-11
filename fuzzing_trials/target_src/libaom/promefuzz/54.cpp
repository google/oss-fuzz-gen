// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control_typechecked_AV1E_SET_ENABLE_ORDER_HINT at aomcx.h:2129:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_WEDGE at aomcx.h:2174:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_MASKED_COMP at aomcx.h:2156:1 in aomcx.h
// aom_codec_control_typechecked_AOME_SET_TUNING at aomcx.h:1965:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC at aomcx.h:2207:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_OVERLAY at aomcx.h:2201:1 in aomcx.h
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
#include <cstdint>
#include <cstring>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 6) {
        return 0;
    }

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    codec.name = "Test Codec";

    bool enable_order_hint = Data[0] % 2;
    bool enable_interintra_wedge = Data[1] % 2;
    bool enable_masked_comp = Data[2] % 2;
    int tuning_param = Data[3];
    bool enable_intrabc = Data[4] % 2;
    bool enable_overlay = Data[5] % 2;

    aom_codec_err_t res;

    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_ORDER_HINT(&codec, AV1E_SET_ENABLE_ORDER_HINT, enable_order_hint);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting order hint: " << res << std::endl;
    }

    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_INTERINTRA_WEDGE(&codec, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_interintra_wedge);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting interintra wedge: " << res << std::endl;
    }

    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_MASKED_COMP(&codec, AV1E_SET_ENABLE_MASKED_COMP, enable_masked_comp);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting masked comp: " << res << std::endl;
    }

    res = aom_codec_control_typechecked_AOME_SET_TUNING(&codec, AOME_SET_TUNING, tuning_param);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting tuning: " << res << std::endl;
    }

    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC(&codec, AV1E_SET_ENABLE_INTRABC, enable_intrabc);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting intrabc: " << res << std::endl;
    }

    res = aom_codec_control_typechecked_AV1E_SET_ENABLE_OVERLAY(&codec, AV1E_SET_ENABLE_OVERLAY, enable_overlay);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Error setting overlay: " << res << std::endl;
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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    