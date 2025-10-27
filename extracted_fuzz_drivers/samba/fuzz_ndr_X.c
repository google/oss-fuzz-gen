/*
   Unix SMB/CIFS implementation.
   Fuzzer for pidl-generated NDR pipes.
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2006
   Copyright (C) Andrew Bartlett 2019
   Copyright (C) Catalyst.NET Ltd 2019

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
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/ndr/libndr.h"
#include "system/filesys.h"
#include "system/locale.h"
#include "util/byteorder.h"

extern const struct ndr_interface_table FUZZ_PIPE_TABLE;

#define FLAG_NDR64 4

enum { TYPE_STRUCT = 0, TYPE_IN, TYPE_OUT };

/*
 * header design (little endian):
 *
 * struct {
 *   uint16_t flags;
 *   uint16_t function_or_struct_no;
 * };
 */

/*
 * We want an even number here to ensure 4-byte alignment later
 * not just for efficiency but because the fuzzers are known to guess
 * that numbers will be 4-byte aligned
 */
#define HEADER_SIZE 4

#define INVALID_FLAGS (~(FLAG_NDR64 | 3))

static const struct ndr_interface_call *find_function(const struct ndr_interface_table *p, unsigned int function_no) {
  if (function_no >= p->num_calls) {
    return NULL;
  }
  return &p->calls[function_no];
}

/*
 * Get a public structure by number and return it as if it were
 * a function.
 */
static const struct ndr_interface_call *find_struct(const struct ndr_interface_table *p, unsigned int struct_no, struct ndr_interface_call *out_buffer) {
  const struct ndr_interface_public_struct *s = NULL;

  if (struct_no >= p->num_public_structs) {
    return NULL;
  }

  s = &p->public_structs[struct_no];

  *out_buffer = (struct ndr_interface_call){.name = s->name, .struct_size = s->struct_size, .ndr_pull = s->ndr_pull, .ndr_push = s->ndr_push, .ndr_print = s->ndr_print};
  return out_buffer;
}

static NTSTATUS pull_chunks(struct ndr_pull *ndr_pull, const struct ndr_interface_call_pipes *pipes) {
  enum ndr_err_code ndr_err;
  uint32_t i;

  for (i = 0; i < pipes->num_pipes; i++) {
    while (true) {
      void *saved_mem_ctx;
      uint32_t *count;
      void *c;

      c = talloc_zero_size(ndr_pull, pipes->pipes[i].chunk_struct_size);
      if (c == NULL) {
        return NT_STATUS_NO_MEMORY;
      }
      /*
       * Note: the first struct member is always
       * 'uint32_t count;'
       */
      count = (uint32_t *)c;

      saved_mem_ctx = ndr_pull->current_mem_ctx;
      ndr_pull->current_mem_ctx = c;
      ndr_err = pipes->pipes[i].ndr_pull(ndr_pull, NDR_SCALARS, c);
      ndr_pull->current_mem_ctx = saved_mem_ctx;

      if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        talloc_free(c);
        return ndr_map_error2ntstatus(ndr_err);
      }
      if (*count == 0) {
        talloc_free(c);
        break;
      }
      talloc_free(c);
    }
  }

  return NT_STATUS_OK;
}

static void ndr_print_and_forget(struct ndr_print *ndr, const char *format, ...) PRINTF_ATTRIBUTE(2, 3);

static char print_buffer[1000000];

static void ndr_print_and_forget(struct ndr_print *ndr, const char *format, ...) {
  /*
   * This is here so that we walk the tree but don't output anything.
   * This helps find buggy ndr_print routines.
   *
   * We call snprinf() to find e.g. strings without NULL terminators.
   */
  va_list list;

  va_start(list, format);
  vsnprintf(print_buffer, sizeof(print_buffer), format, list);
  va_end(list);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t type;
  ndr_flags_type pull_push_print_flags;
  uint16_t fuzz_packet_flags, function;
  TALLOC_CTX *mem_ctx = NULL;
  libndr_flags ndr_flags = 0;
  struct ndr_push *ndr_push;
  enum ndr_err_code ndr_err;
  struct ndr_interface_call f_buffer;
  const struct ndr_interface_call *f = NULL;
  NTSTATUS status;

/*
 * This allows us to build binaries to fuzz just one target function
 *
 * In this mode the input becomes the 'stub data', there is no prefix.
 *
 * There is no NDR64 support in this mode at this time.
 */
#if defined(FUZZ_TYPE) && defined(FUZZ_FUNCTION)
#undef HEADER_SIZE
#define HEADER_SIZE 0
  fuzz_packet_flags = 0;
  type = FUZZ_TYPE;
  function = FUZZ_FUNCTION;
#else
  if (size < HEADER_SIZE) {
    /*
     * the first few bytes decide what is being fuzzed --
     * if they aren't all there we do nothing.
     */
    return 0;
  }

  fuzz_packet_flags = SVAL(data, 0);
  if (fuzz_packet_flags & INVALID_FLAGS) {
    return 0;
  }

  function = SVAL(data, 2);

  type = fuzz_packet_flags & 3;

#ifdef FUZZ_TYPE
  /*
   * Fuzz targets should have as small an interface as possible.
   * This allows us to create 3 binaries for most pipes,
   * TYPE_IN, TYPE_OUT and TYPE_STRUCT
   *
   * We keep the header format, and just exit early if it does
   * not match.
   */
  if (type != FUZZ_TYPE) {
    return 0;
  }
#endif
#endif

  switch (type) {
  case TYPE_STRUCT:
    pull_push_print_flags = NDR_SCALARS | NDR_BUFFERS;
    f = find_struct(&FUZZ_PIPE_TABLE, function, &f_buffer);
    break;
  case TYPE_IN:
    pull_push_print_flags = NDR_IN;
    f = find_function(&FUZZ_PIPE_TABLE, function);
    break;
  case TYPE_OUT:
    pull_push_print_flags = NDR_OUT;
    f = find_function(&FUZZ_PIPE_TABLE, function);
    break;
  default:
    return 0;
  }

  if (f == NULL) {
    return 0;
  }
  if (fuzz_packet_flags & FLAG_NDR64) {
    ndr_flags |= LIBNDR_FLAG_NDR64;
  }

  mem_ctx = talloc_init("ndrfuzz");

  {
    /*
     * f->struct_size is well-controlled, it is essentially
     * defined in the IDL
     */
    uint8_t st[f->struct_size];

    DATA_BLOB blob = data_blob_const(data + HEADER_SIZE, size - HEADER_SIZE);
    struct ndr_pull *ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);

    if (ndr_pull == NULL) {
      perror("ndr_pull_init_blob");
      TALLOC_FREE(mem_ctx);
      return 0;
    }

    /*
     * We must initialise the buffer (even if we would
     * prefer not to for the sake of eg valgrind) as
     * otherwise the special handler for 'out pointer with
     * [size_is()] refers to in value with [ref]' fails to
     * trigger
     */
    memset(st, '\0', sizeof(st));

    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;
    ndr_pull->global_max_recursion = 128;

    if (type == TYPE_OUT) {
      status = pull_chunks(ndr_pull, &f->out_pipes);
      if (!NT_STATUS_IS_OK(status)) {
        TALLOC_FREE(mem_ctx);
        return 0;
      }
    }

    ndr_err = f->ndr_pull(ndr_pull, pull_push_print_flags, st);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
      TALLOC_FREE(mem_ctx);
      return 0;
    }

    if (type == TYPE_IN) {
      status = pull_chunks(ndr_pull, &f->in_pipes);
      if (!NT_STATUS_IS_OK(status)) {
        TALLOC_FREE(mem_ctx);
        return 0;
      }
    }

    ndr_push = ndr_push_init_ctx(mem_ctx);
    if (ndr_push == NULL) {
      TALLOC_FREE(mem_ctx);
      return 0;
    }

    ndr_push->flags |= ndr_flags;

    /*
     * Now push what was pulled, just in case we generated an
     * invalid structure in memory, this should notice
     */
    ndr_err = f->ndr_push(ndr_push, pull_push_print_flags, st);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
      /*
       * Note we aren't bailing here.
       *
       * It is good that ndr_push returned an error, because
       * the structure is no doubt rubbish. But that doesn't
       * mean we don't also want to see if ndr_print can
       * handle it.
       */
    }

    {
      struct ndr_print *ndr_print = talloc_zero(mem_ctx, struct ndr_print);
      ndr_print->print = ndr_print_and_forget;
      ndr_print->depth = 1;

      /*
       * Finally print (to nowhere) the structure, this may also
       * notice invalid memory
       */
      f->ndr_print(ndr_print, f->name, pull_push_print_flags, st);
    }
  }
  TALLOC_FREE(mem_ctx);

  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
