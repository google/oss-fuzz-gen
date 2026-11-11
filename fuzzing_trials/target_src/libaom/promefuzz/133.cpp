// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
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

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, NULL, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Use the first byte of data to decide which control function to call
    uint8_t control_selector = Data[0];
    int enable_flag = Data[1] % 2; // Use the second byte to enable/disable

    switch (control_selector % 6) {
        case 0:
            aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_SMOOTH_INTERINTRA, enable_flag);
            break;
        case 1:
            aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_TX64, enable_flag);
            break;
        case 2:
            aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_ONESIDED_COMP, enable_flag);
            break;
        case 3:
            aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_SUPERRES, enable_flag);
            break;
        case 4: {
            aom_gop_info_t gop_info;
            aom_codec_control(&codec_ctx, AV1E_GET_GOP_INFO, &gop_info);
            break;
        }
        case 5:
            aom_codec_control(&codec_ctx, AV1E_SET_REDUCED_REFERENCE_SET, enable_flag);
            break;
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

        LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    