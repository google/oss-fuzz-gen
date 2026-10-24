#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "/src/libvpx/vpx/vp8cx.h"
#include "/src/libvpx/vpx/vpx_codec.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_codec_dec_cfg_t)) {
        return 0; // Not enough data to initialize the structures
    }

    const char *build_config = vpx_codec_build_config();
    const char *version_extra_str = vpx_codec_version_extra_str();
    const char *version_str = vpx_codec_version_str();

    // Print the build configuration and version information
    std::cout << "Build Config: " << build_config << std::endl;
    std::cout << "Version Extra: " << version_extra_str << std::endl;
    std::cout << "Version: " << version_str << std::endl;

    // Test vpx_codec_iface_name with an invalid interface
    const char *iface_name = vpx_codec_iface_name(nullptr);
    std::cout << "Interface Name (invalid): " << iface_name << std::endl;

    // Initialize codec context and configuration
    vpx_codec_ctx_t ctx;
    vpx_codec_dec_cfg_t cfg;
    std::memset(&ctx, 0, sizeof(vpx_codec_ctx_t)); // Ensure the context is zero-initialized
    std::memcpy(&cfg, Data, sizeof(vpx_codec_dec_cfg_t));

    // Attempt to initialize the decoder
    vpx_codec_err_t res = vpx_codec_dec_init_ver(&ctx, nullptr, &cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        const char *error_detail = vpx_codec_error_detail(&ctx);
        if (error_detail) {
            std::cout << "Error Detail: " << error_detail << std::endl;
        }
    } else {
        // Destroy the codec context if initialized successfully
        vpx_codec_destroy(&ctx);
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
