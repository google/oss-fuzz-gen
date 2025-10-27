/*
  Fuzz sddl conditional ace decoding and encoding
  Copyright (C) Catalyst IT 2023

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "fuzzing/fuzzing.h"
#include "lib/util/attr.h"
#include "libcli/security/conditional_ace.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "replace.h"

#define MAX_LENGTH (1024 * 1024 - 1)
static char sddl_string[MAX_LENGTH + 1] = {0};

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  bool ok;
  struct ace_condition_script *s1 = NULL;
  struct ace_condition_script *s2 = NULL;
  const char *message = NULL;
  size_t message_offset;
  const char *resddl = NULL;
  DATA_BLOB e1, e2, e3;
  size_t length;

  if (len > MAX_LENGTH) {
    return 0;
  }

  memcpy(sddl_string, input, len);
  sddl_string[len] = '\0';

  mem_ctx = talloc_new(NULL);

  s1 = ace_conditions_compile_sddl(mem_ctx, ACE_CONDITION_FLAG_ALLOW_DEVICE, sddl_string, &message, &message_offset, &length);
  if (s1 == NULL) {
    /* could assert message is non-empty */
    TALLOC_FREE(mem_ctx);
    return 0;
  }

  ok = conditional_ace_encode_binary(mem_ctx, s1, &e1);
  if (!ok) {
    abort();
  }

  s2 = parse_conditional_ace(mem_ctx, e1);
  if (s2 == NULL) {
    abort();
  }

  ok = conditional_ace_encode_binary(mem_ctx, s2, &e2);
  if (!ok) {
    abort();
  }
  if (data_blob_cmp(&e1, &e2) != 0) {
    abort();
  }

  /*
   * We know now the SDDL representation compiles to a valid structure
   * that survives a round trip through serialisation.
   *
   * A remaining question is whether it can be re-rendered as SDDL that
   * compiles to the same blob.
   */
  resddl = sddl_from_conditional_ace(mem_ctx, s2);
  if (resddl == NULL) {
    abort();
  }

  s2 = ace_conditions_compile_sddl(mem_ctx, ACE_CONDITION_FLAG_ALLOW_DEVICE, resddl, &message, &message_offset, &length);
  if (s2 == NULL) {
    abort();
  }

  ok = conditional_ace_encode_binary(mem_ctx, s2, &e3);
  if (!ok) {
    abort();
  }
  if (data_blob_cmp(&e1, &e3) != 0) {
    abort();
  }

  TALLOC_FREE(mem_ctx);
  return 0;
}
