#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stddef.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libspectre/ps.h"
#include "../libspectre/spectre-private.h"
#include "../libspectre/spectre-utils.h"
#include "../libspectre/spectre.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f;
  SpectreDocument *document;

/* This is part of the build, it should at least compile on Windows */
#if _POSIX_C_SOURCE >= 200809L
  f = fmemopen((void *)data, size, "rb");
  if (f == NULL)
    return 0;
#endif

  document = spectre_document_new();
  if (document == NULL) {
    fclose(f);
    return 0;
  }

  spectre_document_load_from_stream(document, f);

  if (spectre_document_status(document)) {
    spectre_document_free(document);
    fclose(f);
    return 0;
  }

  spectre_document_free(document);
  fclose(f);

  return 0;
}

#ifdef __cplusplus
}
#endif
