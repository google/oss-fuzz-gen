/*
  Fuzz conditional ace decoding and encoding
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

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  TALLOC_CTX *mem_ctx = NULL;
  bool ok;
  struct ace_condition_script *s1 = NULL;
  struct ace_condition_script *s2 = NULL;
  const char *message = NULL;
  size_t message_offset;
  const char *sddl = NULL;
  DATA_BLOB e1, e2;
  size_t length;

  if (len > MAX_LENGTH) {
    return 0;
  }

  /*
   * In this one we are treating the input data as an ACE blob,
   * and decoding it into the structure and thence SDDL.
   *
   * This doesn't run the conditional ACE, for which we would
   * need a security token.
   */

  e1.data = discard_const(input);
  e1.length = len;

  mem_ctx = talloc_new(NULL);

  s1 = parse_conditional_ace(mem_ctx, e1);
  if (s1 == NULL) {
    /* no worries, it was nonsense */
    TALLOC_FREE(mem_ctx);
    return 0;
  }

  /* back to blob form */
  ok = conditional_ace_encode_binary(mem_ctx, s1, &e2);
  if (!ok) {
    if (e1.length == CONDITIONAL_ACE_MAX_LENGTH) {
      /*
       * This is an edge case where the encoder and
       * decoder treat the boundary slightly
       * differently, and the encoder refuses to
       * encode to the maximum length. This is not
       * an issue in the real world.
       */
      TALLOC_FREE(mem_ctx);
      return 0;
    }
    abort();
  }

  if (data_blob_cmp(&e1, &e2) != 0) {
    abort();
  }

  sddl = sddl_from_conditional_ace(mem_ctx, s1);
  if (sddl == NULL) {
    /*
     * we can't call this a failure, because the blob
     * could easily have nonsensical programs that the
     * SDDL decompiler is unwilling to countenance. For
     * example, it could have an operator that requires
     * arguments as the first token, when of course the
     * arguments need to come first.
     */
    TALLOC_FREE(mem_ctx);
    return 0;
  }

  s2 = ace_conditions_compile_sddl(mem_ctx, ACE_CONDITION_FLAG_ALLOW_DEVICE, sddl, &message, &message_offset, &length);
  if (s2 == NULL) {
    /*
     * We also don't complain when the SDDL decompiler
     * produces an uncompilable program, because the
     * decompiler is meant to be a display tool, not a
     * verifier in itself.
     */
    TALLOC_FREE(mem_ctx);
    return 0;
  }

  ok = conditional_ace_encode_binary(mem_ctx, s2, &e2);
  if (!ok) {
    if (len < CONDITIONAL_ACE_MAX_LENGTH / 4) {
      /*
       * long invalid ACEs can easily result in SDDL that
       * would compile to an over-long ACE, which fail
       * accordingly.
       *
       * But if the original ACE less than a few thousand
       * bytes, and it has been serialised into SDDL, that
       * SDDL should be parsable.
       */
      abort();
    }
  }

  /*
   * It would be nice here to go:
   *
   * if (data_blob_cmp(&e1, &e2) != 0) {
   *       abort();
   * }
   *
   * but that isn't really fair. The decompilation into SDDL
   * does not make thorough sanity checks because that is not
   * its job -- it is just trying to depict what is there -- and
   * there are many ambiguous decompilations.
   *
   * For example, a blob with a single literal integer token,
   * say 42, can only really be shown in the SDDL syntax as
   * "(42)", but when the compiler reads that it knows that a
   * literal number is invalid except in a RHS argument, so it
   * assumes "42" is a local attribute name.
   *
   * Even if the decompiler was a perfect verifier, a round trip
   * through SDDL could not be guaranteed because, for example,
   * an 8 bit integer can only be displayed in SDDL in the form
   * that compiles to a 64 bit integer.
   */

  TALLOC_FREE(mem_ctx);
  return 0;
}
