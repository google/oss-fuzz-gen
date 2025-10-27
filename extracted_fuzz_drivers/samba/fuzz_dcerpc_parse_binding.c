/*
  Fuzz dcerpc_parse_binding
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
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/rpc/dcerpc.h"

#define MAX_LENGTH (1024 * 10)
char buf[MAX_LENGTH + 1];

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  struct dcerpc_binding *binding = NULL;
  struct dcerpc_binding *dup = NULL;
  struct epm_tower tower;
  NTSTATUS status;
  struct GUID guid;

  if (len > MAX_LENGTH) {
    return 0;
  }

  memcpy(buf, input, len);
  buf[len] = '\0';

  mem_ctx = talloc_new(NULL);
  status = dcerpc_parse_binding(mem_ctx, buf, &binding);

  if (!NT_STATUS_IS_OK(status)) {
    talloc_free(mem_ctx);
    return 0;
  }

  /* If the string parses, we try manipulating it a bit */

  dcerpc_binding_string(mem_ctx, binding);
  dcerpc_binding_get_abstract_syntax(binding);
  dup = dcerpc_binding_dup(mem_ctx, binding);

  status = dcerpc_binding_build_tower(mem_ctx, binding, &tower);
  if (NT_STATUS_IS_OK(status)) {
    status = dcerpc_binding_from_tower(mem_ctx, &tower, &dup);
  }

  guid = dcerpc_binding_get_object(binding);

  talloc_free(mem_ctx);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
