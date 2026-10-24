#include <cstdint>
#include <cstddef>
#include <iostream> // Include for debugging output

extern "C" {
    #include <aom/aom_codec.h>
    #include <aom/aom_decoder.h>
    #include <aom/aomdx.h>
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    const aom_codec_iface_t *iface = aom_codec_av1_dx();

    aom_codec_ctx_t codec;
    aom_codec_err_t res = aom_codec_dec_init(&codec, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Failed to initialize codec: " << aom_codec_err_to_string(res) << std::endl;
        return 0;
    }

    res = aom_codec_decode(&codec, data, size, nullptr);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Failed to decode: " << aom_codec_err_to_string(res) << std::endl;
    }

    aom_codec_iter_t iter = nullptr;
    aom_image_t *img = nullptr;
    while ((img = aom_codec_get_frame(&codec, &iter)) != nullptr) {
        // Process the image (img) if needed
    }

    aom_codec_destroy(&codec);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
