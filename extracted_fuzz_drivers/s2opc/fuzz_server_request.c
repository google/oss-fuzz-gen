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
#include "sopc_chunks_mgr_internal.h"
#include "sopc_helper_endianness_cfg.h"
#include "sopc_secure_channels_internal_ctx.h"
#include "sopc_secure_connection_state_mgr.h"
#include "sopc_secure_connection_state_mgr_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (len == 0 || len > UINT32_MAX) {
    return 0;
  }

  SOPC_Helper_Endianness_Check();

  SOPC_Buffer *sopc_buffer = SOPC_Buffer_Create((uint32_t)len);
  SOPC_ASSERT(sopc_buffer != NULL);
  SOPC_ReturnStatus status = SOPC_Buffer_Write(sopc_buffer, buf, (uint32_t)len);
  SOPC_ASSERT(SOPC_STATUS_OK == status);
  SOPC_Buffer_SetPosition(sopc_buffer, 0);

  uint32_t conn_idx;
  bool init = SC_InitNewConnection(&conn_idx);
  SOPC_ASSERT(init);
  SOPC_SecureConnection *sc = SC_GetConnection(conn_idx);
  sc->isServerConnection = true;
  SOPC_SecureConnection_ChunkMgrCtx *chunkCtx = &sc->chunksCtx;
  SOPC_StatusCode errorStatus = SOPC_GoodGenericStatus;
  uint32_t request_id;
  bool ignore_msg;

  while (SOPC_Buffer_Remaining(sopc_buffer) > 0) {
    if (NULL == chunkCtx->currentChunkInputBuffer) {
      // No incomplete message data: create a new buffer
      chunkCtx->currentChunkInputBuffer = SOPC_Buffer_Create(sc->tcpMsgProperties.receiveBufferSize);
      SOPC_ASSERT(chunkCtx->currentChunkInputBuffer != NULL);
    }

    if (!SC_Chunks_DecodeReceivedBuffer(&sc->chunksCtx, sopc_buffer, &errorStatus)) {
      break;
    }

    // Decode OPC UA Secure Conversation MessageChunk specific headers if necessary (not HEL/ACK/ERR)
    if (SC_Chunks_TreatTcpPayload(sc, &request_id, &ignore_msg, &errorStatus)) {
      SOPC_ScInternalContext_ClearInputChunksContext(chunkCtx);
    } else {
      break;
    }
  }

  SC_CloseConnection(conn_idx, true);
  SOPC_Buffer_Delete(chunkCtx->currentChunkInputBuffer);
  SOPC_Buffer_Delete(sopc_buffer);

  return 0;
}
