#include <cstddef>
#include <cstdint>
#include <aom/aom_decoder.h>
#include <aom/aom_codec.h>

extern "C" {
    #include <aom/aom_decoder.h>
    #include <aom/aom_codec.h>
    const aom_codec_iface_t *aom_codec_av1_dx(void);
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_dec_cfg_t cfg = {0}; // Default configuration
    aom_codec_err_t res;

    // Initialize the codec
    res = aom_codec_dec_init(&codec_ctx, aom_codec_av1_dx(), &cfg, 0);
    if (res != AOM_CODEC_OK) {
        return 0; // Initialization failed, exit early
    }

    // Call the function-under-test
    void *user_priv = reinterpret_cast<void *>(0x1); // Non-null user_priv
    res = aom_codec_decode(&codec_ctx, data, size, user_priv);
    
    // Destroy the codec context
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
