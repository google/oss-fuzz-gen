extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
}

#include <fuzzing/datasource/datasource.hpp>

#define CF_CHECK_EQ(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
  if ((expr) != (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }
#define CF_CHECK_NE(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
  if ((expr) == (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }
#define CF_CHECK_GT(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
  if ((expr) <= (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }
#define CF_CHECK_GTE(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        \
  if ((expr) < (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }
#define CF_CHECK_LT(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
  if ((expr) >= (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }
#define CF_CHECK_LTE(expr, res)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        \
  if ((expr) > (res)) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                \
    goto end;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  }

WC_RNG rng;
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (wc_InitRng(&rng) != 0) {
    printf("Cannot initialize wolfCrypt RNG\n");
    abort();
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *out = nullptr;
  size_t outSize;
  RsaKey key;

  CF_CHECK_EQ(wc_InitRsaKey(&key, nullptr), 0);
  try {
    fuzzing::datasource::Datasource ds(data, size);
    auto in = ds.GetData(0);
    const size_t outSize = ds.Get<uint16_t>();
    const auto hashType = ds.Get<uint8_t>() % 20;
    const auto padType = ds.Get<uint8_t>() % 4;
    const auto mgf = ds.Get<uint8_t>() % 30;
    const auto op = ds.Get<uint8_t>();

    const auto useFixedP = ds.Get<bool>();
    const auto useFixedQ = ds.Get<bool>();
    const auto useFixedE = ds.Get<bool>();

    out = (unsigned char *)malloc(outSize);

    if (useFixedP) {
      CF_CHECK_EQ(mp_read_radix(&key.p, "177394230849954131064245255480989004012821188547243082875089817332939117592806928925381076631489487589136913960946519843038016744565956928740258881689624740331770107813730611466172867952263434436405831452577949052393219570107364041547192850493082049277687682777916232840873495339523312601197809902183489687291", 10), 0);
    } else {
      const auto P = ds.Get<std::string>();
      CF_CHECK_EQ(mp_read_radix(&key.p, P.c_str(), 16), 0);
      CF_CHECK_GT(mp_count_bits(&key.p), 0);
    }

    if (useFixedQ) {
      CF_CHECK_EQ(mp_read_radix(&key.q, "139340941162010274272832294124941242931901520848052662860731364542418942420679117400676887176508074074826871632089730259994888733535257022566736634244924563079913368602099396063004498911332974656953172859908423560364533149254536900045466700419633825738672535440706099155268582914038624297110851596697646643437", 10), 0);
    } else {
      const auto Q = ds.Get<std::string>();
      CF_CHECK_EQ(mp_read_radix(&key.q, Q.c_str(), 16), 0);
      CF_CHECK_GT(mp_count_bits(&key.q), 0);
    }

    if (useFixedE) {
      CF_CHECK_EQ(mp_read_radix(&key.e, "65537", 10), 0);
    } else {
      const auto E = ds.Get<std::string>();
      CF_CHECK_EQ(mp_read_radix(&key.e, E.c_str(), 16), 0);
    }

    {
      const auto D = ds.Get<std::string>();
      CF_CHECK_EQ(mp_read_radix(&key.d, D.c_str(), 16), 0);
    }

    CF_CHECK_EQ(mp_mul(&key.p, &key.q, &key.n), 0);

    switch (op) {
    case 0: {
      auto label = ds.GetData(0);
      CF_CHECK_GTE(wc_RsaPublicEncrypt_ex(in.data(), in.size(), out, outSize, &key, &rng, padType, static_cast<enum wc_HashType>(hashType), static_cast<int>(mgf), label.data(), label.size()), 0);
    } break;
    case 1:
      CF_CHECK_GTE(wc_RsaPSS_Sign(in.data(), in.size(), out, outSize, static_cast<enum wc_HashType>(hashType), static_cast<int>(mgf), &key, &rng), 0);
      break;
    case 2:
      CF_CHECK_GTE(wc_RsaSSL_Sign(in.data(), in.size(), out, outSize, &key, &rng), 0);
      break;
    case 3:
      CF_CHECK_GTE(wc_RsaSSL_Verify(in.data(), in.size(), out, outSize, &key), 0);
      break;
    case 4:
      CF_CHECK_GTE(wc_RsaPSS_Verify(in.data(), in.size(), out, outSize, static_cast<enum wc_HashType>(hashType), static_cast<int>(mgf), &key), 0);
      break;
    case 5: {
      auto sig = ds.GetData(0);
      CF_CHECK_EQ(wc_RsaPSS_CheckPadding(in.data(), in.size(), sig.data(), sig.size(), static_cast<enum wc_HashType>(hashType)), 0);
    } break;
    case 6: {
      auto sig = ds.GetData(0);
      CF_CHECK_GTE(wc_RsaPSS_VerifyCheck(in.data(), in.size(), out, outSize, sig.data(), sig.size(), static_cast<enum wc_HashType>(hashType), static_cast<int>(mgf), &key), 0);
    } break;
    }
  } catch (...) {
  }

end:
  wc_FreeRsaKey(&key);
  free(out);
  return 0;
}
