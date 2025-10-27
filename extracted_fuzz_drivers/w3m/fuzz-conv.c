#include "wc.h"
#include "wtf.h"
#include <gc.h>
#include <stdint.h>
#include <stdlib.h>

static void *die_oom(size_t bytes) {
  fprintf(stderr, "Out of memory: %lu bytes unavailable!\n", (unsigned long)bytes);
  exit(1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int init_done = 0;

  if (!init_done) {
    setenv("GC_LARGE_ALLOC_WARN_INTERVAL", "30000", 1);
    GC_INIT();
#if (GC_VERSION_MAJOR > 7) || ((GC_VERSION_MAJOR == 7) && (GC_VERSION_MINOR >= 2))
    GC_set_oom_fn(die_oom);
#else
    GC_oom_fn = die_oom;
#endif
#ifdef USE_M17N
#ifdef USE_UNICODE
    wtf_init(WC_CES_UTF_8, WC_CES_UTF_8);
#else
    wtf_init(WC_CES_EUC_JP, WC_CES_EUC_JP);
#endif
#endif
    init_done = 1;
  }

  /* Assume the data format is:
   *   <str1> \0 <str2> \0 <str3>
   */
  const uint8_t *str1, *str2, *str3;
  const uint8_t *p;
  str1 = data;
  p = memchr(str1, '\0', size);
  if (p == NULL)
    return 0;
  str2 = p + 1;
  if (str2 >= data + size)
    return 0;
  p = memchr(str2, '\0', data + size - str2);
  if (p == NULL)
    return 0;
  str3 = p + 1;

  wc_ces old, from, to;
  from = wc_guess_charset_short((char *)str1, 0);
  to = wc_guess_charset_short((char *)str2, 0);

  Str s = Strnew_charp_n((char *)str3, data + size - str3);
  wc_Str_conv_with_detect(s, &from, from, to);
  Strfree(s);

  return 0;
}
