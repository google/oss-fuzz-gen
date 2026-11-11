// This fuzz driver is generated for library libvpx, aiming to fuzz the following functions:
// vpx_codec_vp9_dx at vp9_dx_iface.c:712:1 in vp8dx.h
// vpx_codec_dec_init_ver at vpx_decoder.c:24:17 in vpx_decoder.h
// vpx_codec_peek_stream_info at vpx_decoder.c:65:17 in vpx_decoder.h
// vpx_codec_decode at vpx_decoder.c:104:17 in vpx_decoder.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_register_put_frame_cb at vpx_decoder.c:133:17 in vpx_decoder.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_get_stream_info at vpx_decoder.c:85:17 in vpx_decoder.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
// vpx_codec_destroy at vpx_codec.c:66:17 in vpx_codec.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fstream>
#include "vpx_decoder.h"
#include "vp8dx.h"
#include "vp8cx.h"

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    // Initialize codec context
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
    vpx_codec_dec_cfg_t cfg = {0}; // Using default configuration
    vpx_codec_err_t res;

    // Initialize the decoder
    res = vpx_codec_dec_init_ver(&codec_ctx, iface, &cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        return 0; // Initialization failed, skip further processing
    }

    // Prepare a dummy file if needed
    std::ofstream dummy_file("./dummy_file", std::ios::binary);
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }

    // Stream info structure
    vpx_codec_stream_info_t stream_info;
    stream_info.sz = sizeof(vpx_codec_stream_info_t);

    // Peek stream info
    res = vpx_codec_peek_stream_info(iface, Data, Size, &stream_info);
    if (res == VPX_CODEC_OK) {
        // Decode the data
        res = vpx_codec_decode(&codec_ctx, Data, static_cast<unsigned int>(Size), nullptr, 0);
        if (res != VPX_CODEC_OK) {
            vpx_codec_destroy(&codec_ctx);
            return 0; // Decoding failed
        }

        // Register a dummy callback
        res = vpx_codec_register_put_frame_cb(&codec_ctx, nullptr, nullptr);
        if (res != VPX_CODEC_OK) {
            vpx_codec_destroy(&codec_ctx);
            return 0; // Callback registration failed
        }

        // Retrieve stream info
        res = vpx_codec_get_stream_info(&codec_ctx, &stream_info);
        if (res != VPX_CODEC_OK) {
            vpx_codec_destroy(&codec_ctx);
            return 0; // Stream info retrieval failed
        }
    }

    // Clean up the codec context
    vpx_codec_destroy(&codec_ctx);
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    