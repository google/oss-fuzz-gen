#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_encoder.h"
#include "vpx/vpx_decoder.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_image_t) + sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_codec_dec_cfg_t)) {
        return 0;
    }

    // Initialize codec contexts
    vpx_codec_ctx_t enc_ctx;
    vpx_codec_ctx_t dec_ctx;

    // Initialize encoder and decoder configuration
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_codec_dec_cfg_t dec_cfg;

    // Initialize image
    vpx_image_t img;
    img.fmt = static_cast<vpx_img_fmt_t>(Data[0] % 10);
    img.cs = static_cast<vpx_color_space_t>(Data[1] % 8);
    img.range = static_cast<vpx_color_range_t>(Data[2] % 2);
    img.w = Data[3] % 256;
    img.planes[0] = const_cast<uint8_t*>(&Data[4]);
    img.stride[0] = 256;
    img.bps = 8;

    // Initialize encoder
    if (vpx_codec_enc_init_ver(&enc_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0, VPX_ENCODER_ABI_VERSION) == VPX_CODEC_OK) {
        // Encode a frame
        vpx_codec_encode(&enc_ctx, &img, 0, 1, 0, 0);
        vpx_codec_destroy(&enc_ctx);
    }

    // Initialize decoder
    if (vpx_codec_dec_init_ver(&dec_ctx, vpx_codec_vp8_dx(), &dec_cfg, 0, VPX_DECODER_ABI_VERSION) == VPX_CODEC_OK) {
        // Decode the data
        vpx_codec_decode(&dec_ctx, Data, Size, nullptr, 0);

        // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from vpx_codec_decode to vpx_codec_get_global_headers using the plateau pool
        vpx_fixed_buf_t* ret_vpx_codec_get_global_headers_chbze = vpx_codec_get_global_headers(&dec_ctx);
        if (ret_vpx_codec_get_global_headers_chbze == NULL){
        	return 0;
        }
        // End mutation: Producer.SPLICE_MUTATOR
        
        vpx_codec_destroy(&dec_ctx);
    }

    // Control function test
    vpx_codec_control_(&enc_ctx, 0); // Random control ID for testing
    vpx_codec_control_(&dec_ctx, 0); // Random control ID for testing

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
