#include <stdint.h>
#include <stddef.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8dx.h>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize codec context
    vpx_codec_ctx_t codec;
    vpx_codec_err_t res;
    
    // Initialize codec interface
    const vpx_codec_iface_t *iface = vpx_codec_vp8_dx();

    // Initialize codec context with decoder interface
    res = vpx_codec_dec_init(&codec, iface, NULL, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Ensure data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Decode the data
        res = vpx_codec_decode(&codec, data, (unsigned int)size, NULL, 0);
    }

    // Destroy codec context
    vpx_codec_destroy(&codec);

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
