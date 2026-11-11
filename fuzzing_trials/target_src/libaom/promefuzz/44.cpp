// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_SMOOTH_INTERINTRA at aomcx.h:2165:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE at aomcx.h:2417:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS at aomcx.h:2111:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY at aomcx.h:2249:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX at aomcx.h:2369:1 in aomcx.h
// aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TEST_VECTOR at aomcx.h:2228:1 in aomcx.h
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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include "aom.h"
#include "aom_codec.h"
#include "aomcx.h"
#include "aom_decoder.h"
#include "aomdx.h"
#include "aom_encoder.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0; // Not enough data to extract an integer
    }

    // Initialize aom_codec_ctx_t
    aom_codec_ctx_t codec_ctx;
    codec_ctx.name = "AV1";
    codec_ctx.iface = aom_codec_av1_cx();
    codec_ctx.err = AOM_CODEC_OK;
    codec_ctx.init_flags = 0;
    codec_ctx.config.enc = nullptr;
    codec_ctx.priv = nullptr;

    // Extract an integer from the input data
    int control_value = *reinterpret_cast<const int*>(Data);

    // Define a control ID for each function
    int ctrl_id_enable_smooth_interintra = AV1E_SET_ENABLE_SMOOTH_INTERINTRA;
    int ctrl_id_screen_content_detection_mode = AV1E_SET_SCREEN_CONTENT_DETECTION_MODE;
    int ctrl_id_enable_rect_partitions = AV1E_SET_ENABLE_RECT_PARTITIONS;
    int ctrl_id_intra_dct_only = AV1E_SET_INTRA_DCT_ONLY;
    int ctrl_id_target_seq_level_idx = AV1E_GET_TARGET_SEQ_LEVEL_IDX;
    int ctrl_id_film_grain_test_vector = AV1E_SET_FILM_GRAIN_TEST_VECTOR;

    // Invoke the target API functions diversely
    aom_codec_control_typechecked_AV1E_SET_ENABLE_SMOOTH_INTERINTRA(&codec_ctx, ctrl_id_enable_smooth_interintra, control_value);
    aom_codec_control_typechecked_AV1E_SET_SCREEN_CONTENT_DETECTION_MODE(&codec_ctx, ctrl_id_screen_content_detection_mode, control_value);
    aom_codec_control_typechecked_AV1E_SET_ENABLE_RECT_PARTITIONS(&codec_ctx, ctrl_id_enable_rect_partitions, control_value);
    aom_codec_control_typechecked_AV1E_SET_INTRA_DCT_ONLY(&codec_ctx, ctrl_id_intra_dct_only, control_value);

    int target_seq_level_idx;
    aom_codec_control_typechecked_AV1E_GET_TARGET_SEQ_LEVEL_IDX(&codec_ctx, ctrl_id_target_seq_level_idx, &target_seq_level_idx);

    aom_codec_control_typechecked_AV1E_SET_FILM_GRAIN_TEST_VECTOR(&codec_ctx, ctrl_id_film_grain_test_vector, control_value);

    // Cleanup
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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    