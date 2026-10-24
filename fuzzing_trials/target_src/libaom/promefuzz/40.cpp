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
#include <cstring>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    int partition_size = 0;
    memcpy(&partition_size, Data, sizeof(int));

    // Initialize codec context
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (aom_codec_enc_init(&codec_ctx, iface, nullptr, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Fuzz target functions
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_PARTITION_SIZE, partition_size);

    if (Size > sizeof(int)) {
        int enable_rect_partitions = Data[sizeof(int)] % 2;
        aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_PARTITIONS, enable_rect_partitions);
    }

    if (Size > sizeof(int) + 1) {
        int intra_dct_only = Data[sizeof(int) + 1] % 2;
        aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DCT_ONLY, intra_dct_only);
    }

    if (Size > sizeof(int) + 2) {
        int enable_smooth_intra = Data[sizeof(int) + 2] % 2;
        aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_SMOOTH_INTRA, enable_smooth_intra);
    }

    if (Size > sizeof(int) + 3) {
        int enable_filter_intra = Data[sizeof(int) + 3] % 2;
        aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_FILTER_INTRA, enable_filter_intra);
    }

    if (Size > sizeof(int) + 4) {
        int enable_rect_tx = Data[sizeof(int) + 4] % 2;
        aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, enable_rect_tx);
    }

    // Destroy codec context
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

        LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    