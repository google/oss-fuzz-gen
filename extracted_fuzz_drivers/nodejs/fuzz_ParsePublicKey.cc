/*
 * A fuzzer focused on FuzzParsePublicKeyPEM
 */

#include "crypto/crypto_context.h"
#include "crypto/crypto_keys.h"
#include "crypto/crypto_util.h"
#include "fuzz_helper.h"
#include <stdlib.h>

using EVPKeyPointer = node::DeleteFnPtr<EVP_PKEY, EVP_PKEY_free>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  EVPKeyPointer pkey;
  node::crypto::ManagedEVPPKey mk;
  mk.FuzzParsePublicKeyPEM(&pkey, reinterpret_cast<const char *>(data), size);
  return 0;
}
