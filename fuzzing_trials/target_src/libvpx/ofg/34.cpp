#include <stdint.h>
#include <stddef.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8cx.h>

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure that the size of the data is sufficient for our needs
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
    vpx_codec_enc_cfg_t cfg;
    unsigned int usage = *(reinterpret_cast<const unsigned int*>(data));

    // Call the function-under-test
    vpx_codec_err_t res = vpx_codec_enc_config_default(iface, &cfg, usage);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
