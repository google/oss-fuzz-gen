/*
  Fuzz a security token and descriptor through an access check
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
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "replace.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  struct security_token_descriptor_fuzzing_pair p = {0};
  enum ndr_err_code ndr_err;
  uint32_t access_granted;

  DATA_BLOB blob = {.data = input, .length = len};

  mem_ctx = talloc_new(NULL);

  ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &p, (ndr_pull_flags_fn_t)ndr_pull_security_token_descriptor_fuzzing_pair);

  if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
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
  sec_access_check_ds(&p.sd, &p.token, p.access_desired, &access_granted, NULL, NULL);
#else
  se_access_check(&p.sd, &p.token, p.access_desired, &access_granted);
#endif

end:
  talloc_free(mem_ctx);
  return 0;
}
