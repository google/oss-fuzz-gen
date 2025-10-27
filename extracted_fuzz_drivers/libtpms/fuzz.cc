#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_nvfilename.h>
#include <libtpms/tpm_types.h>

static void die(const char *msg) {
  fprintf(stderr, "%s", msg);
  assert(false);
}

static TPM_RESULT mytpm_io_init(void) { return TPM_SUCCESS; }

static TPM_RESULT mytpm_io_getlocality(TPM_MODIFIER_INDICATOR *locModif, uint32_t tpm_number) {
  *locModif = 0;

  return TPM_SUCCESS;
}

static TPM_RESULT mytpm_io_getphysicalpresence(TPM_BOOL *phyPres, uint32_t tpm_number) {
  *phyPres = FALSE;

  return TPM_SUCCESS;
}

static unsigned char *permall;
static uint32_t permall_length;

static TPM_RESULT mytpm_nvram_loaddata(unsigned char **data, uint32_t *length, uint32_t tpm_number, const char *name) {
  if (!strcmp(name, TPM_PERMANENT_ALL_NAME)) {
    if (permall) {
      *data = NULL;
      assert(TPM_Malloc(data, permall_length) == TPM_SUCCESS);
      memcpy(*data, permall, permall_length);
      *length = permall_length;
      return TPM_SUCCESS;
    }
  }
  return TPM_RETRY;
}

static TPM_RESULT mytpm_nvram_storedata(const unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name) {
  if (!strcmp(name, TPM_PERMANENT_ALL_NAME)) {
    free(permall);
    permall = NULL;
    assert(TPM_Malloc(&permall, length) == TPM_SUCCESS);
    memcpy(permall, data, length);
    permall_length = length;
  }
  return TPM_SUCCESS;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *rbuffer = NULL;
  uint32_t rlength;
  uint32_t rtotal = 0;
  TPM_RESULT res;
  unsigned char *vol_buffer = NULL;
  uint32_t vol_buffer_len;
  unsigned char *perm_buffer = NULL;
  uint32_t perm_buffer_len;
  unsigned char startup[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00};
  struct libtpms_callbacks cbs = {
      .sizeOfStruct = sizeof(struct libtpms_callbacks),
      .tpm_nvram_init = NULL,
      .tpm_nvram_loaddata = mytpm_nvram_loaddata,
      .tpm_nvram_storedata = mytpm_nvram_storedata,
      .tpm_nvram_deletename = NULL,
      .tpm_io_init = mytpm_io_init,
      .tpm_io_getlocality = mytpm_io_getlocality,
      .tpm_io_getphysicalpresence = mytpm_io_getphysicalpresence,
  };
  res = TPMLIB_RegisterCallbacks(&cbs);
  if (res != TPM_SUCCESS)
    die("Could not register callbacks\n");

  res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
  if (res != TPM_SUCCESS)
    die("Could not choose the TPM version\n");

  res = TPMLIB_MainInit();
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_MainInit() failed\n");

  res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, startup, sizeof(startup));
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_Process(Startup) failed\n");

  res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, (unsigned char *)data, size);
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_Process(fuzz-command) failed\n");

  /* state suspend */
  res = TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &vol_buffer, &vol_buffer_len);
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_GetState(TPMLIB_STATE_VOLATILE) failed\n");

  res = TPMLIB_GetState(TPMLIB_STATE_PERMANENT, &perm_buffer, &perm_buffer_len);
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_GetState(TPMLIB_STATE_PERMANENT) failed\n");

  TPMLIB_Terminate();

  /* state resume */
  res = TPMLIB_SetState(TPMLIB_STATE_PERMANENT, perm_buffer, perm_buffer_len);
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_SetState(TPMLIB_STATE_PERMANENT) failed\n");

  res = TPMLIB_SetState(TPMLIB_STATE_VOLATILE, vol_buffer, vol_buffer_len);
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_SetState(TPMLIB_STATE_VOLATILE) failed\n");

  res = TPMLIB_MainInit();
  if (res != TPM_SUCCESS)
    die("Error: TPMLIB_MainInit() to resume with the state failed\n");

  TPMLIB_Terminate();
  TPM_Free(rbuffer);
  TPM_Free(vol_buffer);
  TPM_Free(perm_buffer);
  TPM_Free(permall);
  permall = NULL;

  return 0;
}
