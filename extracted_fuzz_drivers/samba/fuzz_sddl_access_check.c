/*
  Fuzz access check using SDDL strings and a known token
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
#include "lib/util/bytearray.h"
#include "libcli/security/claims-conversions.h"
#include "libcli/security/conditional_ace.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_conditional_ace.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "replace.h"

static struct security_token token = {0};

static struct dom_sid dom_sid = {0};

/*
 * For this one we initialise a security token to have a few claims
 * and SIDs. The fuzz strings contain SDDL that will be tested against
 * this token in se_access_check() or sec_access_check_ds() --
 * supposing they compile.
 */

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  size_t i;
  TALLOC_CTX *mem_ctx = talloc_new(NULL);
  struct dom_sid *sid = NULL;

  struct claim_def {
    const char *type;
    const char *name;
    const char *claim_sddl;
  } claims[] = {
      {"user", "shoe size", "44"}, {"user", "©", "{\"unknown\", \"\", \" ←ā\"}"}, {"device", "©", "{\"unknown\", \" \", \" ←ā\"}"}, {"device", "least favourite groups", "{SID(S-1-1-0),SID(S-1-5-3),SID(S-1-57777-333-33-33-2)}"}, {"local", "birds", "{\"tern\"}"},
  };

  const char *device_sids[] = {
      "S-1-1-0",
      "S-1-333-66",
      "S-1-2-3-4-5-6-7-8-9",
  };
  const char *user_sids[] = {
      "S-1-333-66",
      "S-1-16-8448",
      "S-1-9-8-7",
  };

  for (i = 0; i < ARRAY_SIZE(user_sids); i++) {
    sid = sddl_decode_sid(mem_ctx, &user_sids[i], NULL);
    if (sid == NULL) {
      abort();
    }
    add_sid_to_array(mem_ctx, sid, &token.sids, &token.num_sids);
  }

  for (i = 0; i < ARRAY_SIZE(device_sids); i++) {
    sid = sddl_decode_sid(mem_ctx, &device_sids[i], NULL);
    if (sid == NULL) {
      abort();
    }
    add_sid_to_array(mem_ctx, sid, &token.device_sids, &token.num_device_sids);
  }

  for (i = 0; i < ARRAY_SIZE(claims); i++) {
    struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim = NULL;
    struct claim_def c = claims[i];

    claim = parse_sddl_literal_as_claim(mem_ctx, c.name, c.claim_sddl);
    if (claim == NULL) {
      abort();
    }
    add_claim_to_token(mem_ctx, &token, claim, c.type);
  }

  /* we also need a global domain SID */
  string_to_sid(&dom_sid, device_sids[2]);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  struct security_descriptor *sd = NULL;
  uint32_t access_desired;
  uint32_t access_granted;
  const char *sddl;
  ssize_t i;
  if (len < 5) {
    return 0;
  }
  access_desired = PULL_LE_U32(input + len - 4, 0);

  /*
   * check there is a '\0'.
   *
   * Note this allows double-dealing for the last 4 bytes: they are used
   * as the access_desired mask (see just above) but also *could* be
   * part of the sddl string. But this doesn't matter, for three
   * reasons:
   *
   * 1. the desired access mask doesn't usually matter much.
   *
   * 2. the final '\0' is rarely the operative one. Usually the
   * effective string ends a long time before the end of the input, and
   * the tail is just junk that comes along for the ride.
   *
   * 3. Even if there is a case where the end of the SDDL is part of the
   * mask, the evolution strategy is very likely to try a different mask,
   * because it likes to add junk on the end.
   *
   * But still, you ask, WHY? So that the seeds from here can be shared
   * back and forth with the fuzz_sddl_parse seeds, which have the same
   * form of a null-terminated-string-with-trailing-junk. If we started
   * the loop at `len - 5` instead of `len - 1`, there might be
   * interesting seeds that are valid there that would fail here. That's
   * all.
   */
  for (i = len - 1; i >= 0; i--) {
    if (input[i] == 0) {
      break;
    }
  }
  if (i < 0) {
    return 0;
  }

  sddl = (const char *)input;
  mem_ctx = talloc_new(NULL);

  sd = sddl_decode(mem_ctx, sddl, &dom_sid);
  if (sd == NULL) {
    goto end;
  }

#ifdef FUZZ_SEC_ACCESS_CHECK_DS
  /*
   * The sec_access_check_ds() function has two arguments not found in
   * se_access_check, and also not found in our fuzzing examples.
   *
   * One is a struct object_tree, which is used for object ACE types.
   * The other is a SID, which is used as a default if an ACE lacks a
   * SID.
   */
  sec_access_check_ds(sd, &token, access_desired, &access_granted, NULL, NULL);
#else
  se_access_check(sd, &token, access_desired, &access_granted);
#endif

end:
  talloc_free(mem_ctx);
  return 0;
}
