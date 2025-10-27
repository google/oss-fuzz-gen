extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/srp.h>
}

#include <fuzzing/datasource/datasource.hpp>

#define CF_CHECK_EQ(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
  if ((expr) != (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Srp srp;
  bool srpInited = false;
  uint8_t *verifier = nullptr;
  uint8_t *pubkey = nullptr;
  uint8_t *proof = nullptr;
  fuzzing::datasource::Datasource ds(data, size);
  try {
    const auto type = ds.Get<SrpType>();
    const auto side = ds.Get<SrpSide>();
    const auto username = ds.GetData(0);
    const auto N = ds.GetData(0);
    const auto g = ds.GetData(0);
    const auto salt = ds.GetData(0);
    const auto password = ds.GetData(0);
    word32 verifierSize = ds.Get<uint16_t>();
    word32 pubkeySize = ds.Get<uint16_t>();
    auto serverPubkey = ds.GetData(0);
    word32 proofSize = ds.Get<uint16_t>();
    auto proof2 = ds.GetData(0);

    verifier = (uint8_t *)malloc(verifierSize);
    pubkey = (uint8_t *)malloc(pubkeySize);
    proof = (uint8_t *)malloc(proofSize);

    CF_CHECK_EQ(wc_SrpInit(&srp, type, side), 0);
    srpInited = true;
    CF_CHECK_EQ(wc_SrpSetUsername(&srp, username.data(), username.size()), 0);
    CF_CHECK_EQ(wc_SrpSetParams(&srp, N.data(), N.size(), g.data(), g.size(), salt.data(), salt.size()), 0);
    CF_CHECK_EQ(wc_SrpSetPassword(&srp, password.data(), password.size()), 0);
    CF_CHECK_EQ(wc_SrpGetVerifier(&srp, verifier, &verifierSize), 0);
    CF_CHECK_EQ(wc_SrpGetPublic(&srp, pubkey, &pubkeySize), 0);
    CF_CHECK_EQ(wc_SrpComputeKey(&srp, pubkey, pubkeySize, serverPubkey.data(), serverPubkey.size()), 0);
    CF_CHECK_EQ(wc_SrpGetProof(&srp, proof, &proofSize), 0);
    CF_CHECK_EQ(wc_SrpVerifyPeersProof(&srp, proof2.data(), proof2.size()), 0);
  } catch (...) {
  }
end:
  if (srpInited == true) {
    /* noret */ wc_SrpTerm(&srp);
  }
  free(verifier);
  free(pubkey);
  free(proof);
  return 0;
}
