/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 - 2022, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_fuzzer.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL URL API.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CURLU *uh;
  char *newp;

  uh = curl_url();

  /* it works on a null-terminated string */
  if (size) {
    newp = (char *)malloc(size + 1);
    if (newp) {
      memcpy(newp, data, size);
      /* make sure it is zero terminated */
      newp[size] = 0;
      curl_url_set(uh, CURLUPART_URL, newp, CURLU_GUESS_SCHEME);
      free(newp);
    }
  }
  curl_url_cleanup(uh);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}
