#include <poppler.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  GError *err = NULL;
  PopplerDocument *doc;
  PopplerPage *page;
  char *buf;
  int npages;
  GList *matches;

  doc = poppler_document_new_from_data((char *)data, size, NULL, &err);
  if (doc == NULL) {
    g_error_free(err);
    return 0;
  }

  npages = poppler_document_get_n_pages(doc);
  if (npages < 1) {
    g_object_unref(doc);
    return 0;
  }

  buf = (char *)calloc(size + 1, sizeof(char));
  memcpy(buf, data, size);
  buf[size] = '\0';

  for (int n = 0; n < npages; n++) {
    page = poppler_document_get_page(doc, n);
    if (!page) {
      continue;
    }
    if (g_utf8_validate(buf, -1, NULL)) {
      matches = poppler_page_find_text(page, buf);
      if (matches) {
        g_list_free_full(matches, (GDestroyNotify)poppler_rectangle_free);
      }
    }
    g_object_unref(page);
  }
  free(buf);
  g_object_unref(doc);
  return 0;
}
