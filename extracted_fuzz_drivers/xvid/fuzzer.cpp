/* Xvid decoder fuzzer by Guido Vranken <guidovranken@gmail.com> */

#include <cstdint>
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <xvid.h>

xvid_gbl_init_t glb;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  memset(&glb, 0, sizeof(glb));
  glb.version = XVID_VERSION;
  if (xvid_global(nullptr, XVID_GBL_INIT, &glb, nullptr)) {
    abort();
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  xvid_dec_stats_t stats;
  xvid_dec_create_t ctx;
  xvid_dec_frame_t frame;

  uint32_t width = 0;
  uint32_t height = 0;
  int remaining = size;

  uint8_t *out = nullptr;
  uint8_t *dataCopy = (uint8_t *)calloc(1, size + 10240);
  memcpy(dataCopy, data, size);

  uint8_t *inptr = dataCopy;

  {
    memset(&ctx, 0, sizeof(ctx));

    ctx.version = XVID_VERSION;
    ctx.width = width;
    ctx.height = height;
  }

  if (xvid_decore(nullptr, XVID_DEC_CREATE, &ctx, nullptr)) {
    abort();
  }

  int loops = 0;
  do {
    {
      memset(&stats, 0, sizeof(xvid_dec_stats_t));
      stats.version = XVID_VERSION;
    }

    {
      memset(&frame, 0, sizeof(xvid_dec_frame_t));

      frame.version = XVID_VERSION;
      frame.general = 0;

      frame.bitstream = inptr;
      frame.length = remaining;

      frame.output.plane[0] = out;
      frame.output.stride[0] = width * 3;

      frame.output.csp = XVID_CSP_BGR;
    }

    const int used_bytes = xvid_decore(ctx.handle, XVID_DEC_DECODE, &frame, &stats);
    if (stats.type == XVID_TYPE_VOL) {
      /* Resize buffer */

      if ((width != stats.data.vol.width) || (height != stats.data.vol.height)) {
        if (width * height < stats.data.vol.width * stats.data.vol.height) {
          if (out) {
            free(out);
          }
          out = (uint8_t *)malloc(stats.data.vol.width * stats.data.vol.height * 4);
        }
        width = stats.data.vol.width;
        height = stats.data.vol.height;
      }
    }

    if (used_bytes > 0) {
      inptr += used_bytes;
      remaining -= used_bytes;
    } else {
      break;
    }

    loops++;
  } while (stats.type <= 0 && remaining > 1);

end:
  free(dataCopy);
  free(out);

  xvid_decore(ctx.handle, XVID_DEC_DESTROY, nullptr, nullptr);
  return 0;
}
