#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib> // Include for 'free'

extern "C" {
    #include "/src/libvpx/vpx/vpx_codec.h"
    #include "/src/libvpx/vpx/vpx_encoder.h"
    #include "/src/libvpx/vpx/vp8cx.h" // Include for 'vpx_codec_vp8_cx'
    #include "/src/libvpx/vpx/vpx_image.h" // Include for 'vpx_image_t' and 'vpx_img_wrap'
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    if (size < 640 * 480 * 3 / 2) { // Ensure the size is enough for a 640x480 I420 image
        return 0;
    }

    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();

    // Initialize codec context and configuration
    if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Set the width and height to some valid values
    cfg.g_w = 640;
    cfg.g_h = 480;

    // Initialize codec
    if (vpx_codec_enc_init(&codec_ctx, iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Use the input data as a frame
    vpx_image_t img;
    if (!vpx_img_wrap(&img, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1, const_cast<uint8_t*>(data))) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Encode the frame
    if (vpx_codec_encode(&codec_ctx, &img, 0, 1, 0, VPX_DL_REALTIME) != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Retrieve the global headers
    vpx_fixed_buf_t *global_headers = vpx_codec_get_global_headers(&codec_ctx);

    // Clean up
    if (global_headers != NULL) {
        free(global_headers->buf);
        free(global_headers);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from vpx_codec_get_global_headers to vpx_codec_set_cx_data_buf
    const vpx_image_t* ret_vpx_codec_get_preview_frame_luqid = vpx_codec_get_preview_frame(&codec_ctx);
    if (ret_vpx_codec_get_preview_frame_luqid == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!global_headers) {
    	return 0;
    }
    vpx_codec_err_t ret_vpx_codec_set_cx_data_buf_sobqe = vpx_codec_set_cx_data_buf(&codec_ctx, global_headers, size, VPX_SS_DEFAULT_LAYERS);
    // End mutation: Producer.APPEND_MUTATOR
    
    vpx_img_free(&img);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
