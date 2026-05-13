// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_error at aom_codec.c:56:13 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_set_option at aom_codec.c:119:17 in aom_codec.h
// aom_codec_decode at aom_decoder.c:94:17 in aom_decoder.h
// aom_obu_type_to_string at aom_codec.c:186:13 in aom_codec.h
// aom_codec_set_frame_buffer_functions at aom_decoder.c:120:17 in aom_decoder.h
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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>

static aom_codec_ctx_t* create_codec_context() {
    aom_codec_ctx_t* ctx = new aom_codec_ctx_t();
    ctx->name = "dummy_codec";
    ctx->iface = nullptr;
    ctx->err = AOM_CODEC_OK;
    ctx->init_flags = 0;
    ctx->priv = nullptr;
    return ctx;
}

static void destroy_codec_context(aom_codec_ctx_t* ctx) {
    if (ctx) delete ctx;
}

extern "C" int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t* ctx = create_codec_context();
    aom_codec_err_t err = static_cast<aom_codec_err_t>(Data[0]);

    // Test aom_codec_error
    const char* error_message = aom_codec_error(ctx);
    if (error_message) {
        // Use the error message somehow
    }

    // Test aom_codec_err_to_string
    const char* err_string = aom_codec_err_to_string(err);
    if (err_string) {
        // Use the error string somehow
    }

    // Test aom_codec_set_option
    if (Size >= 3) {
        const char* option_name = reinterpret_cast<const char*>(Data + 1);
        const char* option_value = reinterpret_cast<const char*>(Data + 2);
        aom_codec_set_option(ctx, option_name, option_value);
    }

    // Test aom_codec_decode
    if (Size > 1) {
        aom_codec_decode(ctx, Data, Size, nullptr);
    }

    // Test aom_obu_type_to_string
    if (Size > 1) {
        OBU_TYPE obu_type = static_cast<OBU_TYPE>(Data[1]);
        const char* obu_string = aom_obu_type_to_string(obu_type);
        if (obu_string) {
            // Use the OBU string somehow
        }
    }

    // Test aom_codec_set_frame_buffer_functions
    aom_codec_set_frame_buffer_functions(ctx, nullptr, nullptr, nullptr);

    destroy_codec_context(ctx);

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

        LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    