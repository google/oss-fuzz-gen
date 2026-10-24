// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_version_extra_str at aom_codec.c:30:13 in aom_codec.h
// aom_codec_build_config at aom_config.c:13:13 in aom_codec.h
// aom_codec_version_str at aom_codec.c:28:13 in aom_codec.h
// aom_codec_version at aom_codec.c:26:5 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_decoder.h"
#include "aom/aom_encoder.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_image.h"
#include "aom/aom_integer.h"
#include "aom/aomcx.h"
#include "aom/aomdx.h"
#include "aom/aom_external_partition.h"

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    // Fuzz aom_codec_version_extra_str
    const char *version_extra_str = aom_codec_version_extra_str();
    if (version_extra_str) {
        printf("Version Extra: %s\n", version_extra_str);
    }

    // Fuzz aom_codec_build_config
    const char *build_config_str = aom_codec_build_config();
    if (build_config_str) {
        printf("Build Config: %s\n", build_config_str);
    }

    // Fuzz aom_codec_version_str
    const char *version_str = aom_codec_version_str();
    if (version_str) {
        printf("Version String: %s\n", version_str);
    }

    // Fuzz aom_codec_version
    int version = aom_codec_version();
    printf("Version Integer: %d\n", version);

    // Fuzz aom_codec_enc_config_default
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    unsigned int usage = AOM_USAGE_GOOD_QUALITY;

    if (Size > 0) {
        usage = Data[0] % 3; // Random usage based on input
    }

    aom_codec_err_t err = aom_codec_enc_config_default(iface, &cfg, usage);
    if (err == AOM_CODEC_OK) {
        printf("Default config obtained successfully.\n");
    } else {
        printf("Failed to obtain default config.\n");
    }

    // Fuzz aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH if it were available
    // As function signature is not provided, this part is commented out
    // if (Size > 0) {
    //     const char *dummy_path = "./dummy_file";
    //     FILE *file = fopen(dummy_path, "wb");
    //     if (file) {
    //         fwrite(Data, 1, Size, file);
    //         fclose(file);
    //     }
    //     // Assuming the function signature is something like:
    //     // aom_codec_err_t aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH(aom_codec_ctx_t *ctx, const char *path);
    //     aom_codec_ctx_t ctx;
    //     err = aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH(&ctx, dummy_path);
    //     if (err == AOM_CODEC_OK) {
    //         printf("VMAF model path set successfully.\n");
    //     } else {
    //         printf("Failed to set VMAF model path.\n");
    //     }
    // }

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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    