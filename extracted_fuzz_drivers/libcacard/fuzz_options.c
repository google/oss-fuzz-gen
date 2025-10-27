/* Copyright (c) 2020, Red Hat, Inc.
 *
 * Authors:  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include <libcacard.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzer.h"
#include "vcard_emul_type.h"

/* Copied internal structures from vcard_emul_nss.c */
struct VirtualReaderOptionsStruct {
  char *name;
  char *vname;
  VCardEmulType card_type;
  char *type_params;
  char **cert_name;
  int cert_count;
};

struct VCardEmulOptionsStruct {
  char *nss_db;
  struct VirtualReaderOptionsStruct *vreader;
  int vreader_count;
  VCardEmulType hw_card_type;
  char *hw_type_params;
  int use_hw;
};

/* We do not want to fuzz inputs longer than 1024 bytes to avoid need for
 * dynamic reallocation inside of the fuzzer. Anything longer should be
 * possible to express with shorter strings
 */
size_t kMaxInputLength = 1024;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int i, j;
  VCardEmulOptions *options = NULL;
  struct VCardEmulOptionsStruct *my_options = NULL;
  char args[1025];

  if (Size > kMaxInputLength) {
    g_debug("Too long input option");
    return 0;
  }

  memcpy(args, Data, Size);
  args[Size] = '\0';
  options = vcard_emul_options(args);
  if (options == NULL) {
    /* Invalid input -- the function should have cleaned up for itself */
    return 0;
  }

  /* There is no sensible way to free options if they were valid */
  my_options = (struct VCardEmulOptionsStruct *)options;
  for (i = 0; i < my_options->vreader_count; i++) {
    g_free(my_options->vreader[i].name);
    g_free(my_options->vreader[i].vname);
    g_free(my_options->vreader[i].type_params);
    for (j = 0; j < my_options->vreader[i].cert_count; j++) {
      g_free(my_options->vreader[i].cert_name[j]);
    }
    g_free(my_options->vreader[i].cert_name);
  }
  g_free(my_options->vreader);
  g_free(my_options->hw_type_params);
  g_free(my_options->nss_db);
  /* The invalid pointers will be overwritten on next call to parse the options */

  return 0;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
