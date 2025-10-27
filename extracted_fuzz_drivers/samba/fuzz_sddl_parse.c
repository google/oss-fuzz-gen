/*
  Fuzz sddl decoding and encoding
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
#include "includes.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "util/charset/charset.h"

#define MAX_LENGTH (100 * 1024 - 1)
static char sddl_string[MAX_LENGTH + 1] = {0};
static struct dom_sid dom_sid = {0};

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  string_to_sid(&dom_sid, "S-1-5-21-2470180966-3899876309-2637894779");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  struct security_descriptor *sd1 = NULL;
  struct security_descriptor *sd2 = NULL;
  char *result = NULL;
  bool ok;

  if (len > MAX_LENGTH) {
    return 0;
  }

  memcpy(sddl_string, input, len);
  sddl_string[len] = '\0';

  mem_ctx = talloc_new(NULL);

  sd1 = sddl_decode(mem_ctx, sddl_string, &dom_sid);
  if (sd1 == NULL) {
    goto end;
  }
  result = sddl_encode(mem_ctx, sd1, &dom_sid);
  if (result == NULL) {
    /*
     * Because Samba currently doesn't enforce strict
     * utf-8 parsing, illegal utf-8 sequences in
     * sddl_string could have ferried bad characters
     * through into the security descriptor conditions
     * that we then find we can't encode.
     *
     * The proper solution is strict UTF-8 enforcement in
     * sddl_decode, but for now we forgive unencodable
     * security descriptors made from bad utf-8.
     */
    size_t byte_len, char_len, utf16_len;
    ok = utf8_check(sddl_string, len, &byte_len, &char_len, &utf16_len);
    if (!ok) {
      goto end;
    }
    /* utf-8 was fine, but we couldn't encode! */
    abort();
  }

  sd2 = sddl_decode(mem_ctx, result, &dom_sid);
  if (sd2 == NULL) {
    if (strlen(result) > CONDITIONAL_ACE_MAX_LENGTH) {
      /*
       * This could fail if a unicode string or
       * attribute name that contains escapable
       * bytes (e.g '\x0b') in an unescaped form in
       * the original string ends up with them in
       * the escaped form ("%000b") in the result
       * string, making the entire attribute name
       * too long for the arbitrary limit we set for
       * SDDL attribute names.
       *
       * We could increase that arbitrary limit (to,
       * say, CONDITIONAL_ACE_MAX_LENGTH * 5), but
       * that is getting very far from real world
       * needs.
       */
      goto end;
    }
    abort();
  }
  ok = security_descriptor_equal(sd1, sd2);
  if (!ok) {
    abort();
  }
end:
  talloc_free(mem_ctx);
  return 0;
}
