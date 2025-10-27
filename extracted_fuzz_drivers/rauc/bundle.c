#include <glib.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <stdio.h>

#include <bundle.h>
#include <config_file.h>
#include <context.h>

#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  g_autofree gchar *tmpdir = NULL;
  g_autofree gchar *bundlename = NULL;
  g_autoptr(RaucBundle) bundle = NULL;
  g_autoptr(GError) error = NULL;

  fuzz_set_logging_func();

  tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
  g_assert_nonnull(tmpdir);

  r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-1.cert.pem");
  r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-1.pem");
  r_context();

  bundlename = g_build_filename(tmpdir, "fuzz-bundle.raucb", NULL);
  g_assert_nonnull(bundlename);
  g_file_set_contents(bundlename, (gchar *)data, size, &error);

  (void)check_bundle(bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &error);

  g_free(r_context()->certpath);
  g_free(r_context()->keypath);
  g_remove(bundlename);
  g_remove(tmpdir);

  return 0;
}
