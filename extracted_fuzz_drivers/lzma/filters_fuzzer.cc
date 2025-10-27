/**
 *
 * @copyright Copyright (c) 2019 Joachim Bauch <mail@joachim-bauch.de>
 *
 * @license GNU GPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include "7zCrc.h"
#include "Aes.h"
#include "Bra.h"
#include "Delta.h"
#include "Sha256.h"
#include "XzCrc64.h"

class FilterFuzzer {
public:
  FilterFuzzer(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  virtual ~FilterFuzzer() = default;

  virtual void RunFuzzer() = 0;

protected:
  const uint8_t *data_;
  size_t size_;
};

class SevenzCrcFuzzer : public FilterFuzzer {
public:
  SevenzCrcFuzzer(const uint8_t *data, size_t size) : FilterFuzzer(data, size) { CrcGenerateTable(); }

  void RunFuzzer() override { CrcCalc(data_, size_); }
};

class XzCrcFuzzer : public FilterFuzzer {
public:
  XzCrcFuzzer(const uint8_t *data, size_t size) : FilterFuzzer(data, size) { Crc64GenerateTable(); }

  void RunFuzzer() override { Crc64Calc(data_, size_); }
};

class EncodeDecodeFuzzer : public FilterFuzzer {
public:
  EncodeDecodeFuzzer(const uint8_t *data, size_t size) : FilterFuzzer(data, size) {}

  void RunFuzzer() override {
    Byte *tmp = static_cast<Byte *>(malloc(size_));
    assert(tmp);
    memcpy(tmp, data_, size_);
    RunFilter(tmp, size_);
    assert(memcmp(tmp, data_, size_) == 0);
    free(tmp);
  }

protected:
  static const UInt32 kIp = 0;

  virtual void RunFilter(uint8_t *data, size_t size) = 0;
};

class BraArmFuzzer : public EncodeDecodeFuzzer {
public:
  BraArmFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    // Encode data.
    ARM_Convert(data, size, kIp, 1);

    // Decode data.
    ARM_Convert(data, size, kIp, 0);
  }
};

class BraArmtFuzzer : public EncodeDecodeFuzzer {
public:
  BraArmtFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    // Encode data.
    ARMT_Convert(data, size, kIp, 1);

    // Decode data.
    ARMT_Convert(data, size, kIp, 0);
  }
};

class BraIa64Fuzzer : public EncodeDecodeFuzzer {
public:
  BraIa64Fuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    // Encode data.
    IA64_Convert(data, size, kIp, 1);

    // Decode data.
    IA64_Convert(data, size, kIp, 0);
  }
};

class BraPpcFuzzer : public EncodeDecodeFuzzer {
public:
  BraPpcFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    // Encode data.
    PPC_Convert(data, size, kIp, 1);

    // Decode data.
    PPC_Convert(data, size, kIp, 0);
  }
};

class BraSparcFuzzer : public EncodeDecodeFuzzer {
public:
  BraSparcFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    // Encode data.
    SPARC_Convert(data, size, kIp, 1);

    // Decode data.
    SPARC_Convert(data, size, kIp, 0);
  }
};

class BraX86Fuzzer : public EncodeDecodeFuzzer {
public:
  BraX86Fuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    UInt32 state;
    // Encode data.
    x86_Convert_Init(state);
    x86_Convert(data, size, kIp, &state, 1);

    // Decode data.
    x86_Convert_Init(state);
    x86_Convert(data, size, kIp, &state, 0);
  }
};

class DeltaFuzzer : public EncodeDecodeFuzzer {
public:
  DeltaFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) {}

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    if (!size) {
      return;
    }

    // We are using up to the first "kDeltaCount" bytes to determine the
    // "delta" value for the filter.
    uint8_t delta = 0;
    static const size_t kDeltaCount = 32;
    for (size_t i = 0; i < std::min(size, kDeltaCount); i++) {
      delta += data[i];
    }
    if (!delta || !size) {
      return;
    }

    Byte state[DELTA_STATE_SIZE];
    Delta_Init(state);
    Delta_Encode(state, delta, data, size);

    Delta_Init(state);
    Delta_Decode(state, delta, data, size);
  }
};

class AesFuzzer : public EncodeDecodeFuzzer {
public:
  AesFuzzer(const uint8_t *data, size_t size) : EncodeDecodeFuzzer(data, size) { AesGenTables(); }

protected:
  void RunFilter(uint8_t *data, size_t size) override {
    if (size < AES_BLOCK_SIZE) {
      // Need at least one block to process.
      return;
    }

    Byte key[AES_BLOCK_SIZE];
    memcpy(key, data, AES_BLOCK_SIZE);

    static const size_t kAlignment = 16;
    static const size_t kAesDataSize = (AES_NUM_IVMRK_WORDS + AES_BLOCK_SIZE) * sizeof(UInt32);
    UInt32 *state = nullptr;
    Byte *iv = nullptr;

    posix_memalign(reinterpret_cast<void **>(&state), kAlignment, kAesDataSize);
    posix_memalign(reinterpret_cast<void **>(&iv), kAlignment, AES_BLOCK_SIZE);
    assert(state);
    assert(iv);
    memcpy(iv, data, AES_BLOCK_SIZE);

    // Encrypt.
    AesCbc_Init(state, iv);
    Aes_SetKey_Enc(state + 4, key, sizeof(key));
    g_AesCbc_Encode(state, data, size / AES_BLOCK_SIZE);

    // Decrypt.
    AesCbc_Init(state, iv);
    Aes_SetKey_Dec(state + 4, key, sizeof(key));
    g_AesCbc_Decode(state, data, size / AES_BLOCK_SIZE);
    free(iv);
    free(state);
  }
};

class Sha256Fuzzer : public FilterFuzzer {
public:
  Sha256Fuzzer(const uint8_t *data, size_t size) : FilterFuzzer(data, size) {}

  void RunFuzzer() override {
    Byte digest[SHA256_DIGEST_SIZE];
    Sha256_Init(&sha256_);
    Sha256_Update(&sha256_, data_, size_);
    Sha256_Final(&sha256_, digest);
  }

private:
  CSha256 sha256_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size) {
    return 0;
  }

  FilterFuzzer *fuzzers[] = {
      new AesFuzzer(data, size), new BraArmFuzzer(data, size), new BraArmtFuzzer(data, size), new BraIa64Fuzzer(data, size), new BraPpcFuzzer(data, size), new BraSparcFuzzer(data, size), new BraX86Fuzzer(data, size), new DeltaFuzzer(data, size), new SevenzCrcFuzzer(data, size), new Sha256Fuzzer(data, size), new XzCrcFuzzer(data, size),
  };
  for (FilterFuzzer *fuzzer : fuzzers) {
    fuzzer->RunFuzzer();
    delete fuzzer;
  };
  return 0;
}
