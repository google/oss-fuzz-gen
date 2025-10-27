/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
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

extern "C" {
#include "curl_fnmatch.h"
#include <curl/curl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
}

/* #define DEBUG(STMT)  STMT */
#define DEBUG(STMT)

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL fnmatch function.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *string_data = (const char *)data;
  const char *pattern;
  const char *contents;
  int pattern_len;
  int fnrc;

  DEBUG(printf("\nSize is %lu bytes \n", size));

  /* The string requires at least two null terminators. Anything
     smaller is an error. */
  if (size < 2) {
    DEBUG(printf("Size is too small. \n"));
    goto EXIT_LABEL;
  }

  /* The data should be split into two strings - the pattern and the
     string to match on. The data should be null-terminated. */
  if (data[size - 1] != 0) {
    DEBUG(printf("Not null terminated \n"));
    goto EXIT_LABEL;
  }

  pattern_len = strnlen(string_data, size);

  DEBUG(printf("Pattern length %d \n", pattern_len));

  /* Check to see if the string length is valid. Because pattern_len
     doesn't include a null terminator, we should check to see if the length
     equals the full buffer size with or without a null terminator. */
  if ((pattern_len >= size - 1) || (string_data[pattern_len] != 0)) {
    /* The string was not valid. */
    DEBUG(printf("Pattern string was invalid \n"));
    goto EXIT_LABEL;
  }

  /* Set up the pointers for the pattern and string. */
  pattern = string_data;
  contents = &string_data[pattern_len + 1];

  /* Sanity check the size of the strings. We should have two strings
     less two null terminators. */
  if (strlen(contents) + pattern_len != size - 2) {
    DEBUG(printf("Unexpected lengths: %lu + %d != %lu - 2 \n", strlen(contents), pattern_len, size));
    goto EXIT_LABEL;
  }

  DEBUG(printf("Pattern: '%s' \n", pattern));
  DEBUG(printf("Contents: '%s' \n", contents));

  /* Call the fuzz function. */
  fnrc = Curl_fnmatch(NULL, pattern, contents);

  (void)fnrc;
  DEBUG(printf("Curl_fnmatch returned %d \n", fnrc));

EXIT_LABEL:

  return 0;
}
