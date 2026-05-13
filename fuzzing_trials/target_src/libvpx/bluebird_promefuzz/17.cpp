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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "vpx/vpx_decoder.h"
#include "/src/libvpx/vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "/src/libvpx/vpx/vpx_codec.h"

static void dummy_frame_callback(void *user_priv, const vpx_image_t *img) {
  // Dummy callback function for put frame
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_codec_dec_cfg_t)) {
    return 0;
  }

  vpx_codec_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));

  vpx_codec_dec_cfg_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.threads = 1;

  // Assuming iface is a valid pointer to a codec interface
  const vpx_codec_iface_t *iface = vpx_codec_vp8_dx(); // Example using VP8 decoder interface

  vpx_codec_err_t res = vpx_codec_dec_init_ver(&ctx, iface, &cfg, 0, VPX_DECODER_ABI_VERSION);
  if (res != VPX_CODEC_OK) {
    return 0;
  }

  vpx_codec_register_put_frame_cb(&ctx, dummy_frame_callback, nullptr);

  vpx_codec_caps_t caps = vpx_codec_get_caps(iface);

  const char *error_detail = vpx_codec_error_detail(&ctx);
  const char *error_msg = vpx_codec_error(&ctx);

  if (Size > 0) {
    res = vpx_codec_decode(&ctx, Data, static_cast<unsigned int>(Size), nullptr, 0);
  }

  vpx_codec_destroy(&ctx);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
