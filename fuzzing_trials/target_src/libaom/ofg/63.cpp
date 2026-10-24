#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <aom/aom_codec.h>
    #include <aom/aom_decoder.h>
    #include <aom/aomdx.h> // Include the header for AV1 decoder interface
}

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Declare and initialize variables
    aom_codec_ctx_t codec_ctx;
    aom_codec_stream_info_t stream_info;

    // Initialize codec context and stream info with valid values
    aom_codec_iface_t *iface = aom_codec_av1_dx(); // Use AV1 decoder interface
    aom_codec_err_t res = aom_codec_dec_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        return 0; // Initialization failed
    }

    // Feed the data to the decoder
    res = aom_codec_decode(&codec_ctx, data, size, nullptr);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0; // Decoding failed
    }

    // Get stream info
    res = aom_codec_get_stream_info(&codec_ctx, &stream_info);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0; // Getting stream info failed
    }

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
