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
#include "sopc_buffer.h"
#include "sopc_encodeabletype.h"
#include "sopc_helper_endianness_cfg.h"
#include "sopc_mem_alloc.h"
#include "sopc_types.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if ((len <= 1) || ((2 * len) > UINT32_MAX)) {
    return 0;
  }

  SOPC_Helper_Endianness_Check();

  const size_t type_index = buf[0] % SOPC_TypeInternalIndex_SIZE;

  /* get an encodeable type by looking in encodeableType array */
  SOPC_EncodeableType *type = SOPC_KnownEncodeableTypes[type_index];

  void *pValue = SOPC_Calloc(1, type->AllocationSize);
  if (NULL == pValue) {
    return 0;
  }

  SOPC_EncodeableObject_Initialize(type, pValue);

  /* create a buffer using remaining data */
  SOPC_Buffer *buffer = SOPC_Buffer_Attach((uint8_t *)&buf[1], (uint32_t)len - 1);

  SOPC_ReturnStatus status = SOPC_EncodeableObject_Decode(type, pValue, buffer, 0);
  /*  encode if decode was successful */
  if (SOPC_STATUS_OK == status) {
    SOPC_Buffer *result_buffer = SOPC_Buffer_CreateResizable((uint32_t)len - 1, (uint32_t)(2 * len));
    if (NULL == result_buffer) {
      status = SOPC_STATUS_OUT_OF_MEMORY;
    }
    if (SOPC_STATUS_OK == status) {
      status = SOPC_EncodeableObject_Encode(type, pValue, result_buffer, 0);
      /* we should succeed in encoding what we just decoded */
      SOPC_ASSERT(SOPC_STATUS_OK == status);
      /* we cannot verify that buffer == result_buffer since some things might vary
       * such as string length for empty string etc. */

      /* decode what we just encoded */
      if (SOPC_STATUS_OK == status) {
        void *pValue2 = SOPC_Calloc(1, type->AllocationSize);
        if (NULL == pValue2) {
          status = SOPC_STATUS_OUT_OF_MEMORY;
        }
        if (SOPC_STATUS_OK == status) {
          status = SOPC_Buffer_SetPosition(result_buffer, 0);
        }
        if (SOPC_STATUS_OK == status) {
          status = SOPC_EncodeableObject_Decode(type, pValue2, result_buffer, 0);
          SOPC_ASSERT(SOPC_STATUS_OK == status);

          /* encode again */
          SOPC_Buffer *result_buffer2 = SOPC_Buffer_CreateResizable((uint32_t)len - 1, (uint32_t)(2 * len));
          if (NULL == result_buffer2) {
            status = SOPC_STATUS_OUT_OF_MEMORY;
          }
          if (SOPC_STATUS_OK == status) {
            status = SOPC_EncodeableObject_Encode(type, pValue2, result_buffer2, 0);
            /* we should succeed in encoding what we just decoded */
            SOPC_ASSERT(SOPC_STATUS_OK == status);
            /* compare result_buffer2 with result buffer */
            /* we should have the same buffers */
            SOPC_ASSERT(result_buffer2->length == result_buffer->length);
            SOPC_ASSERT(0 == memcmp(result_buffer2->data, result_buffer->data, result_buffer2->length));
          }

          SOPC_Buffer_Delete(result_buffer2);
          SOPC_EncodeableObject_Clear(type, pValue2);
          SOPC_Free(pValue2);
        }
      }
    }
    SOPC_Buffer_Delete(result_buffer);
    SOPC_EncodeableObject_Clear(type, pValue);
  }

  /* clear */
  SOPC_Free(buffer); // delete tries to free data which is also freed by libfuzzer
  SOPC_Free(pValue);

  return 0;
}
