#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

extern "C" {
    vpx_codec_iface_t * vpx_codec_vp9_dx();
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Call the function-under-test
    vpx_codec_iface_t *iface = vpx_codec_vp9_dx();

    if (iface != NULL) {
        vpx_codec_ctx_t codec;
        vpx_codec_err_t res = vpx_codec_dec_init(&codec, iface, NULL, 0);
        if (res == VPX_CODEC_OK) {
            // Attempt to decode the input data
            vpx_codec_err_t decode_res = vpx_codec_decode(&codec, data, size, NULL, 0);
            if (decode_res == VPX_CODEC_OK) {
                // Retrieve frame to ensure the data is processed
                vpx_codec_iter_t iter = NULL;
                vpx_image_t *img = NULL;
                while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
                    // Process the image if needed
                }
            }
            // Destroy the codec context after use
            vpx_codec_destroy(&codec);
        }
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
