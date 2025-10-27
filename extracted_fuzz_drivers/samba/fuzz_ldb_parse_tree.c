/*
   Fuzzing for ldb_parse_tree
   Copyright (C) Michael Hanselmann 2019

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
#include "ldb.h"
#include "ldb_module.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  TALLOC_CTX *mem_ctx = talloc_init(__FUNCTION__);
  struct ldb_parse_tree *tree;
  char *filter;

  if (len < 1) {
    goto out;
  }

  filter = talloc_strndup(mem_ctx, (const char *)buf, len);

  if (filter == NULL) {
    goto out;
  }

  tree = ldb_parse_tree(mem_ctx, filter);

  (void)ldb_filter_from_tree(mem_ctx, tree);

out:
  talloc_free(mem_ctx);

  return 0;
}
