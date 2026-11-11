// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_err_to_string at aom_codec.c:36:13 in aom_codec.h
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
#include <aom/aom.h>
#include <aom/aom_codec.h>
#include <aom/aom_encoder.h>
#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <aom/aom_external_partition.h>
#include <aom/aom_frame_buffer.h>
#include <aom/aom_image.h>
#include <aom/aom_integer.h>

static void fuzz_codec_control(aom_codec_ctx_t *ctx, int control_id, int value) {
  aom_codec_err_t res = aom_codec_control(ctx, control_id, value);
  if (res != AOM_CODEC_OK) {
    fprintf(stderr, "Error in codec control: %s\n", aom_codec_err_to_string(res));
  }
}

extern "C" int LLVMFuzzerTestOneInput_110(const uint8_t *Data, size_t Size) {
  if (Size < 1) return 0;

  aom_codec_ctx_t codec_ctx;
  memset(&codec_ctx, 0, sizeof(codec_ctx));

  aom_codec_iface_t *iface = aom_codec_av1_cx();
  if (!iface) return 0;

  aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, iface, nullptr, 0);
  if (res != AOM_CODEC_OK) {
    fprintf(stderr, "Error initializing codec: %s\n", aom_codec_err_to_string(res));
    return 0;
  }

  int enable_flag = Data[0] % 2;

  fuzz_codec_control(&codec_ctx, AV1E_SET_ENABLE_SMOOTH_INTERINTRA, enable_flag);
  fuzz_codec_control(&codec_ctx, AV1E_SET_ENABLE_INTERINTRA_WEDGE, enable_flag);
  fuzz_codec_control(&codec_ctx, AV1E_SET_ENABLE_ONESIDED_COMP, enable_flag);
  fuzz_codec_control(&codec_ctx, AV1E_SET_ENABLE_WARPED_MOTION, enable_flag);
  fuzz_codec_control(&codec_ctx, AV1E_SET_ENABLE_SUPERRES, enable_flag);

  aom_gop_info_t gop_info;
  res = aom_codec_control(&codec_ctx, AV1E_GET_GOP_INFO, &gop_info);
  if (res != AOM_CODEC_OK) {
    fprintf(stderr, "Error getting GOP info: %s\n", aom_codec_err_to_string(res));
  }

  res = aom_codec_destroy(&codec_ctx);
  if (res != AOM_CODEC_OK) {
    fprintf(stderr, "Error destroying codec: %s\n", aom_codec_err_to_string(res));
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

        LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    