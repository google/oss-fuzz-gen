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
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "/src/aom/aom/aom_encoder.h"
#include "/src/aom/aom/aomcx.h"
#include "aom/aomdx.h"
#include "aom/aom_decoder.h"
#include "/src/aom/aom/aom_external_partition.h"
#include "/src/aom/aom/aom_integer.h"
#include "/src/aom/aom/aom_frame_buffer.h"
#include "/src/aom/aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Dummy initialization values
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    aom_codec_enc_cfg_t cfg;
    aom_codec_enc_config_default(iface, &cfg, 0);

    if (aom_codec_enc_init(&codec_ctx, iface, &cfg, 0)) {
        std::cerr << "Failed to initialize codec." << std::endl;
        return 0;
    }

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_PARTITION_INFO_PATH
    const char *partition_info_path = "./dummy_partition_info_path";
    FILE *dummy_file = fopen(partition_info_path, "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }
    aom_codec_control(&codec_ctx, AV1E_SET_PARTITION_INFO_PATH, partition_info_path);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_RTC_EXTERNAL_RC
    int rtc_external_rc = static_cast<int>(Data[0]);
    aom_codec_control(&codec_ctx, AV1E_SET_RTC_EXTERNAL_RC, rtc_external_rc);

    // Fuzzing aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX
    int target_seq_level_idx;
    aom_codec_control(&codec_ctx, AV1E_GET_TARGET_SEQ_LEVEL_IDX, &target_seq_level_idx);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TABLE
    const char *film_grain_table_path = "./dummy_film_grain_table";
    dummy_file = fopen(film_grain_table_path, "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }
    aom_codec_control(&codec_ctx, AV1E_SET_FILM_GRAIN_TABLE, film_grain_table_path);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_VMAF_MODEL_PATH
    const char *vmaf_model_path = "./dummy_vmaf_model";
    dummy_file = fopen(vmaf_model_path, "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }
    aom_codec_control(&codec_ctx, AV1E_SET_VMAF_MODEL_PATH, vmaf_model_path);

    // Fuzzing aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_TX
    int enable_rect_tx = Data[0] % 2; // boolean flag
    aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_RECT_TX, enable_rect_tx);

    // Cleanup
    if (aom_codec_destroy(&codec_ctx)) {
        std::cerr << "Failed to destroy codec." << std::endl;
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
