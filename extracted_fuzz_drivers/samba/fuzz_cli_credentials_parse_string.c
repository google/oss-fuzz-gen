/*
  Fuzz cli_credentials_parse_string
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
#include "auth/credentials/credentials.h"
#include "fuzzing/fuzzing.h"
#include "includes.h"

#define MAX_LENGTH (1024 * 10)
char buf[MAX_LENGTH + 1];

const enum credentials_obtained obtained = CRED_UNINITIALISED;

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  struct cli_credentials *credentials = NULL;
  bool anon;
  const char *username;
  const char *domain;

  if (len > MAX_LENGTH) {
    return 0;
  }

  memcpy(buf, input, len);
  buf[len] = '\0';

  mem_ctx = talloc_new(NULL);
  credentials = cli_credentials_init(mem_ctx);

  cli_credentials_parse_string(credentials, buf, obtained);

  anon = cli_credentials_is_anonymous(credentials);

  cli_credentials_get_ntlm_username_domain(credentials, mem_ctx, &username, &domain);

  talloc_free(mem_ctx);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
