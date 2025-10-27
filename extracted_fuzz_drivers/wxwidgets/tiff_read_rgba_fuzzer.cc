/* Copyright (c) 1988-1997 Sam Leffler
 * Copyright (c) 1991-1997 Silicon Graphics, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that (i) the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation, and (ii) the names of
 * Sam Leffler and Silicon Graphics may not be used in any advertising or
 * publicity relating to the software without the specific, prior written
 * permission of Sam Leffler and Silicon Graphics.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <tiffio.h>
#include <tiffio.hxx>

/* stolen from tiffiop.h, which is a private header so we can't just include it */
/* safe multiply returns either the multiplied value or 0 if it overflowed */
#define __TIFFSafeMultiply(t, v, m) ((((t)(m) != (t)0) && (((t)(((v) * (m)) / (m))) == (t)(v))) ? (t)((v) * (m)) : (t)0)

const uint64 MAX_SIZE = 500000000;

extern "C" void handle_error(const char *unused, const char *unused2, va_list unused3) { return; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifndef STANDALONE
  TIFFSetErrorHandler(handle_error);
  TIFFSetWarningHandler(handle_error);
#endif
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
  // libjpeg-turbo has issues with MSAN and SIMD code
  // See https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=7547
  // and https://github.com/libjpeg-turbo/libjpeg-turbo/pull/365
  setenv("JSIMD_FORCENONE", "1", 1);
#endif
#endif
  std::istringstream s(std::string(Data, Data + Size));
  TIFF *tif = TIFFStreamOpen("MemTIFF", &s);
  if (!tif) {
    return 0;
  }
  uint32 w, h;
  uint32 *raster;

  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
  TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
  /* don't continue if file size is ludicrous */
  if (TIFFTileSize64(tif) > MAX_SIZE) {
    TIFFClose(tif);
    return 0;
  }
  uint64 bufsize = TIFFTileSize64(tif);
  /* don't continue if the buffer size greater than the max allowed by the fuzzer */
  if (bufsize > MAX_SIZE || bufsize == 0) {
    TIFFClose(tif);
    return 0;
  }
  /* another hack to work around an OOM in tif_fax3.c */
  uint32 tilewidth = 0;
  uint32 imagewidth = 0;
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tilewidth);
  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &imagewidth);
  tilewidth = __TIFFSafeMultiply(uint32, tilewidth, 2);
  imagewidth = __TIFFSafeMultiply(uint32, imagewidth, 2);
  if (tilewidth * 2 > MAX_SIZE || imagewidth * 2 > MAX_SIZE || tilewidth == 0 || imagewidth == 0) {
    TIFFClose(tif);
    return 0;
  }
  uint32 size = __TIFFSafeMultiply(uint32, w, h);
  if (size > MAX_SIZE || size == 0) {
    TIFFClose(tif);
    return 0;
  }
  raster = (uint32 *)_TIFFmalloc(size * sizeof(uint32));
  if (raster != NULL) {
    TIFFReadRGBAImage(tif, w, h, raster, 0);
    _TIFFfree(raster);
  }
  TIFFClose(tif);

  return 0;
}

#ifdef STANDALONE

template <class T> static void CPL_IGNORE_RET_VAL(T) {}

static void Usage(int, char *argv[]) {
  fprintf(stderr, "%s [--help] [-repeat N] filename.\n", argv[0]);
  exit(1);
}

int main(int argc, char *argv[]) {
  int nRet = 0;
  void *buf = NULL;
  int nLen = 0;
  int nLoops = 1;
  const char *pszFilename = NULL;

  for (int i = 1; i < argc; i++) {
    if (i + 1 < argc && strcmp(argv[i], "-repeat") == 0) {
      nLoops = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-dummy") == 0) {
      uint8_t dummy = ' ';
      return LLVMFuzzerTestOneInput(&dummy, 1);
    } else if (strcmp(argv[i], "--help") == 0) {
      Usage(argc, argv);
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unrecognized option: %s", argv[i]);
      Usage(argc, argv);
    } else {
      pszFilename = argv[i];
    }
  }
  if (pszFilename == nullptr) {
    fprintf(stderr, "No filename specified\n");
    Usage(argc, argv);
  }
  FILE *f = fopen(pszFilename, "rb");
  if (!f) {
    fprintf(stderr, "%s does not exist.\n", pszFilename);
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  nLen = (int)ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = malloc(nLen);
  if (!buf) {
    fprintf(stderr, "malloc failed.\n");
    fclose(f);
    exit(1);
  }
  CPL_IGNORE_RET_VAL(fread(buf, nLen, 1, f));
  fclose(f);
  for (int i = 0; i < nLoops; i++) {
    nRet = LLVMFuzzerTestOneInput(static_cast<const uint8_t *>(buf), nLen);
    if (nRet != 0)
      break;
  }
  free(buf);
  return nRet;
}

#endif
