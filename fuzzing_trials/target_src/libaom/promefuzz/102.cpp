// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_av1_cx at av1_cx_iface.c:5345:20 in aomcx.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_enc_config_set at aom_encoder.c:298:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_encode at aom_encoder.c:168:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_set_cx_data_buf at aom_encoder.c:244:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <iostream>
#include <cstring>
#include <cstdint>
#include "aom.h"
#include "aom_codec.h"
#include "aom_encoder.h"
#include "aom_decoder.h"
#include "aom_image.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(aom_codec_ctx_t) + sizeof(aom_codec_enc_cfg_t)) {
    return 0;
  }

  aom_codec_ctx_t codec_ctx;
  aom_codec_enc_cfg_t enc_cfg;
  std::memcpy(&codec_ctx, Data, sizeof(codec_ctx));
  std::memcpy(&enc_cfg, Data + sizeof(codec_ctx), sizeof(enc_cfg));

  // Initialize codec
  aom_codec_err_t res = aom_codec_enc_init(&codec_ctx, aom_codec_av1_cx(), &enc_cfg, 0);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // Fuzz aom_codec_control with AOME_SET_MAX_INTER_BITRATE_PCT
  if (Size > sizeof(codec_ctx) + sizeof(enc_cfg)) {
    int bitrate_pct = Data[sizeof(codec_ctx) + sizeof(enc_cfg)] % 1000; // Example range
    aom_codec_control(&codec_ctx, AV1E_SET_MAX_INTER_BITRATE_PCT, bitrate_pct);
  }

  // Fuzz aom_codec_control with AV1E_SET_CHROMA_SUBSAMPLING_X
  if (Size > sizeof(codec_ctx) + sizeof(enc_cfg) + 1) {
    int subsampling_x = Data[sizeof(codec_ctx) + sizeof(enc_cfg) + 1] % 2; // Example range
    aom_codec_control(&codec_ctx, AV1E_SET_CHROMA_SUBSAMPLING_X, subsampling_x);
  }

  // Fuzz aom_codec_enc_config_set
  res = aom_codec_enc_config_set(&codec_ctx, &enc_cfg);
  if (res != AOM_CODEC_OK) {
    aom_codec_destroy(&codec_ctx);
    return 0;
  }

  // Fuzz aom_codec_control with AV1E_SET_FILM_GRAIN_TABLE
  if (Size > sizeof(codec_ctx) + sizeof(enc_cfg) + 2) {
    const char* film_grain_table = reinterpret_cast<const char*>(Data + sizeof(codec_ctx) + sizeof(enc_cfg) + 2);
    aom_codec_control(&codec_ctx, AV1E_SET_FILM_GRAIN_TABLE, film_grain_table);
  }

  // Fuzz aom_codec_encode
  aom_image_t img;
  std::memset(&img, 0, sizeof(img));
  aom_codec_pts_t pts = 0;
  unsigned long duration = 1;
  aom_enc_frame_flags_t flags = 0;
  res = aom_codec_encode(&codec_ctx, &img, pts, duration, flags);
  if (res != AOM_CODEC_OK) {
    aom_codec_destroy(&codec_ctx);
    return 0;
  }

  // Fuzz aom_codec_set_cx_data_buf
  if (Size > sizeof(codec_ctx) + sizeof(enc_cfg) + 3) {
    aom_fixed_buf_t buf;
    buf.buf = (void*)(Data + sizeof(codec_ctx) + sizeof(enc_cfg) + 3);
    buf.sz = Size - (sizeof(codec_ctx) + sizeof(enc_cfg) + 3);
    unsigned int pad_before = 0;
    unsigned int pad_after = 0;
    aom_codec_set_cx_data_buf(&codec_ctx, &buf, pad_before, pad_after);
  }

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

        LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    