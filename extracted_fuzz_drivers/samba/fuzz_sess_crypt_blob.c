/*
   Fuzzing sess_*crypt_blob
   Copyright (C) Catalyst IT 2020

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
#include "libcli/auth/libcli_auth.h"
#include "session.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  DATA_BLOB blob, session_key, out;
  size_t slen;
  if (len < 1) {
    return 0;
  }

  slen = input[0];
  if (len < slen + 1) {
    return 0;
  }

  session_key.data = input + 1;
  session_key.length = slen;
  blob.data = input + 1 + slen;
  blob.length = len - slen - 1;

  mem_ctx = talloc_new(NULL);

  out = sess_encrypt_blob(mem_ctx, &blob, &session_key);
  sess_decrypt_blob(mem_ctx, &blob, &session_key, &out);

  TALLOC_FREE(mem_ctx);
  return 0;
}
