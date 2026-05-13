#include <cstdint>
#include <cstdlib>
#include <vpx/vpx_decoder.h>

extern "C" {
    #include <vpx/vp8dx.h> // Include the header where vpx_codec_vp8_dx is declared
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    vpx_codec_ctx_t codec_ctx;
    void *user_priv = (void *)0x1; // Non-NULL pointer for user_priv
    long deadline = 0; // Deadline parameter

    // Initialize the codec context
    if (vpx_codec_dec_init(&codec_ctx, vpx_codec_vp8_dx(), NULL, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Call the function-under-test
    vpx_codec_err_t result = vpx_codec_decode(&codec_ctx, data, static_cast<unsigned int>(size), user_priv, deadline);

    // Destroy the codec context
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
