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

static aom_codec_ctx_t initialize_codec() {
    aom_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    return codec;
}

static void fuzz_codec_control_functions(aom_codec_ctx_t *codec, const uint8_t *Data, size_t Size) {
    if (Size < 6) return;

    unsigned int param1 = Data[0] % 4;  // Example for chroma subsampling levels
    unsigned int param2 = Data[1] % 3;  // Example for delta-lambda factor modes
    unsigned int param3 = Data[2] % 2;  // Boolean for skip postproc filtering
    unsigned int param4 = Data[3] % 5;  // Example for coefficient cost update frequency
    unsigned int param5 = Data[4] % 256; // Example for VBR corpus complexity
    unsigned int param6 = Data[5] % 10;  // Example for GF min pyramid height

    aom_codec_control(codec, AV1E_SET_CHROMA_SUBSAMPLING_X, param1);
    aom_codec_control(codec, AV1E_SET_DELTALF_MODE, param2);
    aom_codec_control(codec, AV1E_SET_SKIP_POSTPROC_FILTERING, param3);
    aom_codec_control(codec, AV1E_SET_COEFF_COST_UPD_FREQ, param4);
    aom_codec_control(codec, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, param5);
    aom_codec_control(codec, AV1E_SET_GF_MIN_PYRAMID_HEIGHT, param6);
}

extern "C" int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec = initialize_codec();

    fuzz_codec_control_functions(&codec, Data, Size);

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

        LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    