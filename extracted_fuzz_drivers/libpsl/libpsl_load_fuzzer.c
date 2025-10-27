/*
 * Copyright(c) 2017-2024 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libpsl.
 */

#include <config.h>

#include <assert.h> /* assert */

#ifdef HAVE_STDINT_H
#include <stdint.h> /* uint8_t */
#elif defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
#endif

#include <stdio.h>  /* fmemopen */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "fuzzer.h"
#include "libpsl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#ifdef HAVE_FMEMOPEN
  FILE *fp;
  psl_ctx_t *psl;

  fp = fmemopen((void *)data, size, "r");
  if (!fp && size) /* libc6 < 2.22 return NULL when size == 0 */
    assert(1);

  psl = psl_load_fp(fp);
  psl_is_public_suffix(NULL, NULL);
  psl_is_public_suffix(psl, ".ü.com");

  psl_free(psl);
  if (fp)
    fclose(fp);

  psl_load_file("/dev/null");
#endif

  return 0;
}
