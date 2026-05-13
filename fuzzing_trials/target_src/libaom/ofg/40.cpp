#include <cstdint>
#include <cstdlib>

extern "C" {
    #include <aom/aom_decoder.h>
    #include <aom/aom_codec.h>
    #include <aom/aomdx.h> // Include this header to declare aom_codec_av1_dx
}

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Initialize the codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();
    aom_codec_err_t res = aom_codec_dec_init(&codec_ctx, iface, NULL, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Use the input data to decode a frame
    res = aom_codec_decode(&codec_ctx, data, size, NULL);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Initialize an iterator
    aom_codec_iter_t iter = NULL;

    // Call the function-under-test
    aom_image_t *image = aom_codec_get_frame(&codec_ctx, &iter);

    // Clean up
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
