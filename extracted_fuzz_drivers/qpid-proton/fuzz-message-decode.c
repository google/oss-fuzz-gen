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

#include <stdint.h>

#include "proton/message.h"

#include "libFuzzingEngine.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    // pn_message_decode would die on assert
    return 0;
  }
  pn_message_t *msg = pn_message();
  int ret = pn_message_decode(msg, (const char *)Data, Size);
  if (ret == 0) {
    // FUTURE: do something like encode msg and compare again with Data
  }
  if (msg != NULL) {
    pn_message_free(msg);
  }
  return 0;
}
