#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "/src/aom/aom/aomcx.h"
#include "/src/aom/aom/aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(int)) return 0;

  aom_codec_ctx_t codec_ctx;
  aom_codec_iface_t *iface = aom_codec_av1_cx();
  aom_codec_enc_cfg_t cfg;
  aom_codec_err_t res;

  res = aom_codec_enc_config_default(iface, &cfg, 0);
  if (res != AOM_CODEC_OK) return 0;

  res = aom_codec_enc_init(&codec_ctx, iface, &cfg, 0);
  if (res != AOM_CODEC_OK) return 0;

  int param = 0;
  std::memcpy(&param, Data, sizeof(int));

  // Fuzz aom_codec_control_typechecked_AV1E_SET_GF_MAX_PYRAMID_HEIGHT
  aom_codec_control(&codec_ctx, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, param);

  // Fuzz aom_codec_control_typechecked_AV1E_SET_MODE_COST_UPD_FREQ
  aom_codec_control(&codec_ctx, AV1E_SET_MODE_COST_UPD_FREQ, param);

  // Fuzz aom_codec_control_typechecked_AV1E_SET_MIN_CR
  aom_codec_control(&codec_ctx, AV1E_SET_MIN_CR, param);

  // Fuzz aom_codec_control_typechecked_AV1E_SET_ENABLE_TX_SIZE_SEARCH
  aom_codec_control(&codec_ctx, AV1E_SET_ENABLE_TX_SIZE_SEARCH, param);

  // Fuzz aom_codec_control_typechecked_AV1E_SET_COEFF_COST_UPD_FREQ
  aom_codec_control(&codec_ctx, AV1E_SET_COEFF_COST_UPD_FREQ, param);

  // Fuzz aom_codec_control_typechecked_AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP
  aom_codec_control(&codec_ctx, AV1E_SET_VBR_CORPUS_COMPLEXITY_LAP, param);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
