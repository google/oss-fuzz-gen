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
#include "sopc_helper_endianness_cfg.h"
#include "sopc_network_layer.h"
#include "sopc_reader_layer.h"

#define BUFFER_INITIAL_LEN (4096)
#define BUFFER_MAX_LEN (1u << 30)

static const uint32_t subGroupVersion = 963852;
static const uint32_t subGroupId = 1245;

static SOPC_PubSubConfiguration *configuration = NULL;
static SOPC_PubSubConnection *subConnection = NULL;

static SOPC_Buffer *sopc_buffer = NULL;

static void setupConnection(void) {
  SOPC_FieldMetaData *meta = NULL;
  SOPC_ReaderGroup *subReader = NULL;
  SOPC_DataSetReader *dsReader = NULL;
  configuration = SOPC_PubSubConfiguration_Create();
  SOPC_ASSERT(NULL != configuration);
  // "udp_pub_test"
  SOPC_PubSubConfiguration_Allocate_SubConnection_Array(configuration, 1);
  subConnection = SOPC_PubSubConfiguration_Get_SubConnection_At(configuration, 0);

  SOPC_PubSubConnection_Allocate_ReaderGroup_Array(subConnection, 2);
  subReader = SOPC_PubSubConnection_Get_ReaderGroup_At(subConnection, 0);

  SOPC_ReaderGroup_Set_SecurityMode(subReader, SOPC_SecurityMode_None);
  SOPC_ReaderGroup_Allocate_DataSetReader_Array(subReader, 1);
  dsReader = SOPC_ReaderGroup_Get_DataSetReader_At(subReader, 0);
  SOPC_ReaderGroup_Set_GroupId(subReader, (uint16_t)subGroupId);
  SOPC_ReaderGroup_Set_GroupVersion(subReader, subGroupVersion);
  SOPC_ReaderGroup_Set_PublisherId_UInteger(subReader, 15300);

  SOPC_DataSetReader_Set_DataSetWriterId(dsReader, 123);

  SOPC_DataSetReader_Allocate_FieldMetaData_Array(dsReader, SOPC_TargetVariablesDataType, 5);
  SOPC_PubSub_ArrayDimension arrDimension = {.valueRank = -1, .arrayDimensions = NULL};
  // Var 1
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 0);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_UInt32_Id);
  // Var 2
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 1);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_Byte_Id);
  // Var 3
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 2);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_UInt16_Id);
  // Var 4
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 3);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_DateTime_Id);
  // Var 5
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 4);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_UInt32_Id);

  // Configuration for "udp_pub_conf_test"
  subReader = SOPC_PubSubConnection_Get_ReaderGroup_At(subConnection, 1);

  SOPC_ReaderGroup_Set_SecurityMode(subReader, SOPC_SecurityMode_None);
  SOPC_ReaderGroup_Allocate_DataSetReader_Array(subReader, 1);
  dsReader = SOPC_ReaderGroup_Get_DataSetReader_At(subReader, 0);
  SOPC_ReaderGroup_Set_GroupId(subReader, (uint16_t)45612);
  SOPC_ReaderGroup_Set_GroupVersion(subReader, 123456);
  //    SOPC_ReaderGroup_Set_PublisherId_UInteger(subReader, 15300);

  SOPC_DataSetReader_Set_DataSetWriterId(dsReader, 12);

  SOPC_DataSetReader_Allocate_FieldMetaData_Array(dsReader, SOPC_TargetVariablesDataType, 4);
  // Var 1
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 0);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_UInt16_Id);
  // Var 2
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 1);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_DateTime_Id);
  // Var 3
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 2);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_UInt32_Id);
  // Var 4
  meta = SOPC_DataSetReader_Get_FieldMetaData_At(dsReader, 3);
  SOPC_ASSERT(NULL != meta);
  SOPC_FieldMetaData_ArrayDimension_Move(meta, &arrDimension);
  SOPC_FieldMetaData_Set_BuiltinType(meta, SOPC_String_Id);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  setupConnection();
  SOPC_Helper_Endianness_Check();
  sopc_buffer = SOPC_Buffer_CreateResizable(BUFFER_INITIAL_LEN, BUFFER_MAX_LEN);
  SOPC_ASSERT(sopc_buffer != NULL);

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (len == 0 || len > UINT32_MAX) {
    return 0;
  }

  /* FIXME: Avoid messages with String PublisherId which are known to raise an assert in the subscriber code */
  if ((len >= 2) && (buf[0] & 0x80) && ((buf[1] & 0x07) == DataSet_LL_PubId_String_Id)) {
    return 0;
  }

  SOPC_Buffer_SetPosition(sopc_buffer, 0);
  SOPC_ReturnStatus status = SOPC_Buffer_Write(sopc_buffer, buf, (uint32_t)len);
  SOPC_ASSERT(SOPC_STATUS_OK == status);
  sopc_buffer->length = sopc_buffer->position;
  SOPC_Buffer_SetPosition(sopc_buffer, 0);

  SOPC_ASSERT(NULL != subConnection);
  const SOPC_UADP_NetworkMessage_Reader_Configuration readerConf = {.pGetSecurity_Func = NULL, .callbacks = SOPC_Reader_NetworkMessage_Default_Readers, .checkDataSetMessageSN_Func = NULL, .updateTimeout_Func = NULL, .targetVariable_Func = NULL, .targetConfig = NULL};

  SOPC_UADP_NetworkMessage *uadp_nm = NULL;
  SOPC_UADP_NetworkMessage_Decode(sopc_buffer, &readerConf, subConnection, &uadp_nm);

  if (NULL != uadp_nm)
    SOPC_UADP_NetworkMessage_Delete(uadp_nm);

  return 0;
}
