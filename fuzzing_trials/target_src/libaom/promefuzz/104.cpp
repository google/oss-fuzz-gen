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

extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    int ctrl_id;
    int data_value;

    // Fuzzing AV1E_SET_ENABLE_SMOOTH_INTERINTRA
    ctrl_id = AV1E_SET_ENABLE_SMOOTH_INTERINTRA;
    data_value = Data[0] % 2;
    aom_codec_control(&codec, ctrl_id, data_value);

    // Fuzzing AV1E_SET_ENABLE_INTERINTRA_WEDGE
    ctrl_id = AV1E_SET_ENABLE_INTERINTRA_WEDGE;
    data_value = Data[1] % 2;
    aom_codec_control(&codec, ctrl_id, data_value);

    // Fuzzing AV1E_SET_ENABLE_ONESIDED_COMP
    ctrl_id = AV1E_SET_ENABLE_ONESIDED_COMP;
    data_value = Data[2] % 2;
    aom_codec_control(&codec, ctrl_id, data_value);

    // Fuzzing AV1E_SET_ENABLE_WARPED_MOTION
    ctrl_id = AV1E_SET_ENABLE_WARPED_MOTION;
    data_value = Data[3] % 2;
    aom_codec_control(&codec, ctrl_id, data_value);

    // Fuzzing AV1E_SET_ENABLE_SUPERRES
    ctrl_id = AV1E_SET_ENABLE_SUPERRES;
    data_value = Data[4] % 2;
    aom_codec_control(&codec, ctrl_id, data_value);

    // Fuzzing AV1E_GET_GOP_INFO
    aom_gop_info_t gop_info;
    ctrl_id = AV1E_GET_GOP_INFO;
    aom_codec_control(&codec, ctrl_id, &gop_info);

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

        LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    