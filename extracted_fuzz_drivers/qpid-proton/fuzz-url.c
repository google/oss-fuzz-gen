/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#define PN_USE_DEPRECATED_API

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "proton/url.h"

#include "libFuzzingEngine.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // null-terminate the string in Data in case it doesn't contain null already
  char *str = (char *)malloc(Size + 1);
  memcpy(str, Data, Size);
  str[Size] = '\0';

  pn_url_t *url = pn_url_parse(str);
  if (url != NULL) {
    pn_url_free(url);
  }

  free(str);
  return 0;
}

#undef PN_USE_DEPRECATED_API
