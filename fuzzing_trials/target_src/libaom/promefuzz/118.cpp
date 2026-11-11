// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_control_typechecked_AV1E_SET_PARTITION_INFO_PATH at aomcx.h:2327:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TABLE at aomcx.h:2231:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS at aomcx.h:2381:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC at aomcx.h:2360:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TEST_VECTOR at aomcx.h:2228:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH at aomcx.h:2300:1 in aomcx.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <fstream>
#include <cstring>
#include <aom/aom_codec.h>
#include <aom/aomcx.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_integer.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) return 0;

    std::string dummy_path = "./dummy_file";
    std::ofstream dummy_file(dummy_path);
    dummy_file.write(reinterpret_cast<const char *>(Data), Size);
    dummy_file.close();

    // Create a dummy control ID for demonstration purposes
    int dummy_ctrl_id = 0;

    // Test aom_codec_control_typechecked_AV1E_SET_PARTITION_INFO_PATH
    res = aom_codec_control_typechecked_AV1E_SET_PARTITION_INFO_PATH(&codec_ctx, dummy_ctrl_id, dummy_path.c_str());
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Test aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TABLE
    res = aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TABLE(&codec_ctx, dummy_ctrl_id, dummy_path.c_str());
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Test aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS
    int quantizer = static_cast<int>(Data[0]);
    res = aom_codec_control_typechecked_AV1E_SET_QUANTIZER_ONE_PASS(&codec_ctx, dummy_ctrl_id, quantizer);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Test aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC
    res = aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC(&codec_ctx, dummy_ctrl_id, 0);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Test aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TEST_VECTOR
    res = aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TEST_VECTOR(&codec_ctx, dummy_ctrl_id, 0);
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

    // Test aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH
    res = aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH(&codec_ctx, dummy_ctrl_id, dummy_path.c_str());
    if (res != AOM_CODEC_OK) {
        aom_codec_destroy(&codec_ctx);
        return 0;
    }

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

        LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    