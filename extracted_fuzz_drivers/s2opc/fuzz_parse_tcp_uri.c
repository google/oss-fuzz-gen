/*
 * Licensed to Systerel under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Systerel licenses this file to you under the Apache
 * License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sopc_assert.h"
#include "sopc_builtintypes.h"
#include "sopc_helper_uri.h"
#include "sopc_mem_alloc.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  /* Make an awkward reference to another translation unit, increasing the complexity of this function.
   * TODO: rework this test to avoid this, maybe by enlarging its scope. */
  static bool init = false;
  static SOPC_String dummy;

  if (!init) {
    SOPC_String_Initialize(&dummy);
    init = true;
  }

  char *buf_copy = SOPC_Calloc(1 + len, sizeof(char));
  SOPC_ASSERT(buf_copy != NULL);

  memcpy(buf_copy, buf, len);

  char *hostname = NULL;
  char *port = NULL;
  SOPC_UriType type = SOPC_URI_UNDETERMINED;
  SOPC_Helper_URI_SplitUri(buf_copy, &type, &hostname, &port);

  SOPC_Free(hostname);
  SOPC_Free(port);
  SOPC_Free(buf_copy);

  return 0;
}
