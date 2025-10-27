#include <dds/security/core/dds_security_serialize.h>
#include <dds/security/core/dds_security_utils.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  {
    DDS_Security_Deserializer dser = DDS_Security_Deserializer_new(data, size);
    DDS_Security_KeyMaterial_AES_GCM_GMAC km;
    memset(&km, 0, sizeof(DDS_Security_KeyMaterial_AES_GCM_GMAC));
    DDS_Security_Deserialize_KeyMaterial_AES_GCM_GMAC(dser, &km);
    DDS_Security_Deserializer_free(dser);
    DDS_Security_KeyMaterial_AES_GCM_GMAC_deinit(&km);
  }

  {
    DDS_Security_ParticipantBuiltinTopicData *pbtd = DDS_Security_ParticipantBuiltinTopicData_alloc();
    DDS_Security_SecurityException ex;
    DDS_Security_Exception_clean(&ex);
    DDS_Security_Deserializer dser = DDS_Security_Deserializer_new(data, size);
    DDS_Security_Deserialize_ParticipantBuiltinTopicData(dser, pbtd, &ex);
    DDS_Security_Deserializer_free(dser);
    DDS_Security_Exception_reset(&ex);
    DDS_Security_ParticipantBuiltinTopicData_free(pbtd);
  }

  return 0;
}
