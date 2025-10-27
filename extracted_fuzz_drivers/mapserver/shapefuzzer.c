#include "src/mapserver.h"
#include "src/mapshape.h"

#include "cpl_vsi.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(GByte *data, size_t size);
extern int LLVMFuzzerInitialize(int *argc, char ***argv);

static void *msMemmem(const void *haystack, size_t haystack_len, const void *const needle, const size_t needle_len) {
  if (haystack_len == 0)
    return NULL;
  if (needle_len == 0)
    return NULL;

  for (const char *h = (const char *)haystack; haystack_len >= needle_len; ++h, --haystack_len) {
    if (!memcmp(h, needle, needle_len)) {
      return (void *)h;
    }
  }
  return NULL;
}

static VSILFILE *SegmentFile(const char *filename, GByte **data_p, size_t *size_p) {
  GByte *data = *data_p;
  size_t size = *size_p;

  GByte *separator = (GByte *)msMemmem(data, size, "deadbeef", 8);
  if (separator != NULL) {
    size = separator - data;
    *data_p = separator + 8;
    *size_p -= size + 8;
  } else {
    *size_p = 0;
  }

  return VSIFileFromMemBuffer(filename, data, size, false);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return 0;
}

int LLVMFuzzerTestOneInput(GByte *data, size_t size) {
  /* this fuzzer expects three files concatenated, separated by the
     string "deadbeef"; you can generate such a file by typing:

     { cat foo.shp; echo -n "deadbeef"; cat foo.shx; echo -n "deadbeef"; cat
     foo.dbf; } >/tmp/corpus/start

     then run the fuzzer:

     ./build/fuzzer/fuzzer /tmp/corpus
  */

  VSILFILE *shp = SegmentFile("/vsimem/foo.shp", &data, &size);
  VSILFILE *shx = SegmentFile("/vsimem/foo.shx", &data, &size);
  VSILFILE *dbf = SegmentFile("/vsimem/foo.dbf", &data, &size);

  shapefileObj file;
  errorObj *ms_error = msGetErrorObj();
  if (msShapefileOpenVirtualFile(&file, "/vsimem/foo.shp", shp, shx, dbf, false) == 0) {
    if (file.numshapes > 100 * 1000) {
      VSIStatBufL sStat;
      if (VSIStatL("/vsimem/foo.shx", &sStat) == 0 && sStat.st_size >= 100 && file.numshapes > (int)(sStat.st_size - 100) / 8) {
        file.numshapes = (int)(sStat.st_size - 100) / 8;
      }
    }
    for (int i = 0; i < file.numshapes; ++i) {
      shapeObj shape;
      msInitShape(&shape);
      msSHPReadShape(file.hSHP, i, &shape);
      msFreeShape(&shape);
      // Give up as soon an error is triggered to avoid too long processing
      // time.
      if (ms_error->code != MS_NOERR)
        break;
    }

    msShapefileClose(&file);
  }

  msResetErrorList();

  VSIUnlink("/vsimem/foo.shp");
  VSIUnlink("/vsimem/foo.shx");
  VSIUnlink("/vsimem/foo.dbf");

  return EXIT_SUCCESS;
}
