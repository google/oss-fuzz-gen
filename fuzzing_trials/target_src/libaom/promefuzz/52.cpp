// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
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
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_decoder.h>
#include <aom/aom_encoder.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_DNL_DENOISING(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int enable_dnl_denoising = data[0] % 2; // Use only the first byte
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_DNL_DENOISING, enable_dnl_denoising);
}

static void fuzz_aom_codec_control_typechecked_AOME_SET_TUNING(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int tuning = data[0] % 3; // Assuming 3 tuning modes
    aom_codec_control(&codec_ctx, AOME_SET_TUNING, tuning);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int reduced_tx_type_set = data[0] % 2; // Use only the first byte
    aom_codec_control(&codec_ctx, AV1E_SET_REDUCED_TX_TYPE_SET, reduced_tx_type_set);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int enable_intrabc = data[0] % 2; // Use only the first byte
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTRABC, enable_intrabc);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_OVERLAY(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int enable_overlay = data[0] % 2; // Use only the first byte
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_OVERLAY, enable_overlay);
}

static void fuzz_aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(aom_codec_ctx_t &codec_ctx, const uint8_t *data, size_t size) {
    if (size < 1) return;
    int intra_default_tx_only = data[0] % 2; // Use only the first byte
    aom_codec_control(&codec_ctx, AV1E_SET_INTRA_DEFAULT_TX_ONLY, intra_default_tx_only);
}

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    if (Size < 1) return 0;

    // Initialize codec context (assuming AV1 encoder interface)
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    // Fuzz each function
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_DNL_DENOISING(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AOME_SET_TUNING(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_REDUCED_TX_TYPE_SET(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_INTRABC(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_ENABLE_OVERLAY(codec_ctx, Data, Size);
    fuzz_aom_codec_control_typechecked_AV1E_SET_INTRA_DEFAULT_TX_ONLY(codec_ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    