// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include "fuzz_ec.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t bitlenFromTlsId(uint16_t tlsid) {
  switch (tlsid) {
  // TODO complete curves from TLS
  case 18:
    // secp192k1
    return 192;
  case 19:
    // secp192r1
    return 192;
  case 20:
    // secp224k1
    return 224;
  case 21:
    // secp224r1
    return 224;
  case 22:
    // secp256k1
    return 256;
  case 23:
    // secp256r1
    return 256;
  case 24:
    // secp384r1
    return 384;
  case 25:
    // secp521r1
    return 521;
  case 26:
    // brainpoolP256r1
    return 256;
  case 27:
    // brainpoolP384r1
    return 384;
  case 28:
    // brainpoolP512r1
    return 512;
  }
  return 0;
}

#define NBMODULES 11
// TODO integrate more modules
void fuzzec_mbedtls_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_libecc_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_openssl_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_nettle_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_gcrypt_process(fuzzec_input_t *input, fuzzec_output_t *output);
int fuzzec_gcrypt_init();
void fuzzec_cryptopp_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_botan_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_botanblind_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_golang_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_js_process(fuzzec_input_t *input, fuzzec_output_t *output);
int fuzzec_js_init();
void fuzzec_rust_process(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_mbedtls_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_libecc_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_openssl_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_gcrypt_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_cryptopp_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_botan_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_golang_add(fuzzec_input_t *input, fuzzec_output_t *output);
void fuzzec_js_add(fuzzec_input_t *input, fuzzec_output_t *output);
fuzzec_module_t modules[NBMODULES] = {
    {
        "mbedtls",
        fuzzec_mbedtls_process,
        fuzzec_mbedtls_add,
        NULL,
    },
    {
        "libecc",
        fuzzec_libecc_process,
        fuzzec_libecc_add,
        NULL,
    },
    {
        "openssl",
        fuzzec_openssl_process,
        fuzzec_openssl_add,
        NULL,
    },
    {
        "nettle",
        fuzzec_nettle_process,
        NULL,
        NULL,
    },
    {
        "gcrypt",
        fuzzec_gcrypt_process,
        fuzzec_gcrypt_add,
        fuzzec_gcrypt_init,
    },
    {
        "cryptopp",
        fuzzec_cryptopp_process,
        fuzzec_cryptopp_add,
        NULL,
    },
    {
        "botan",
        fuzzec_botan_process,
        fuzzec_botan_add,
        NULL,
    },
    {
        "botanblind",
        fuzzec_botanblind_process,
        NULL,
        NULL,
    },
    {
        "golang",
        fuzzec_golang_process,
        fuzzec_golang_add,
        NULL,
    },
    {
        "nodesjs/elliptic",
        fuzzec_js_process,
        fuzzec_js_add,
        fuzzec_js_init,
    },
    {
        "rust",
        fuzzec_rust_process,
        NULL,
        NULL,
    },

};
int decompressPoint(const uint8_t *Data, int compBit, size_t Size, uint8_t *decom, uint16_t tls_id, size_t coordlen);

static int initialized = 0;

static const char *nameOfCurve(uint16_t tlsid) {
  switch (tlsid) {
  case 18:
    return "secp192k1";
  case 19:
    return "secp192r1";
  case 20:
    return "secp224k1";
  case 21:
    return "secp224r1";
  case 22:
    return "secp256k1";
  case 23:
    return "secp256r1";
  case 24:
    return "secp384r1";
  case 25:
    return "secp521r1";
  case 26:
    return "brainpool256r1";
  case 27:
    return "brainpool384r1";
  case 28:
    return "brainpool512r1";
  }
  return "";
}

#define MAX_FAIL_MSG_SIZE 256
static void failTest(uint16_t tlsid, size_t modNb) {
  char *failmsg = malloc(MAX_FAIL_MSG_SIZE);
  snprintf(failmsg, MAX_FAIL_MSG_SIZE - 1, "%s:%s", modules[modNb].name, nameOfCurve(tlsid));
  printf("Assertion failure: %s\n", failmsg);
  fflush(stdout);
#ifndef FUZZ_RECOVER
  abort();
#endif
  free(failmsg);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fuzzec_input_t input;
  fuzzec_output_t output[NBMODULES];
  size_t i, k, lastok;

  if (initialized == 0) {
    for (i = 0; i < NBMODULES; i++) {
      if (modules[i].init) {
        if (modules[i].init()) {
          printf("Failed init for module %s\n", modules[i].name);
          return 0;
        }
      }
    }
    initialized = 1;
  }
  if (Size < 5) {
    // 2 bytes for TLS group, 2 for point, 1 for big integer
    return 0;
  }
  // splits Data in tlsid, point coordinates, big number
  input.tls_id = (Data[0] << 8) | Data[1];
  input.groupBitLen = bitlenFromTlsId(input.tls_id);
  if (input.groupBitLen == 0) {
    // unsupported curve
    return 0;
  }

  Size -= 2;
  if (Size < 1 + 2 * ECDF_BYTECEIL(input.groupBitLen)) {
    // unused bytes
    return 0;
  }
  if (Size > 1 + 2 * ECDF_BYTECEIL(input.groupBitLen)) {
    Size = 1 + 2 * ECDF_BYTECEIL(input.groupBitLen);
  }
  input.coordSize = ECDF_BYTECEIL(input.groupBitLen);
  input.bignumSize = Size / 2;
  input.bignum = Data + 2;
  if (Data[2 + input.bignumSize] & 0x80) {
    // adding 2 points
    if (decompressPoint(Data + 2, (Data[2 + input.bignumSize] & 0x2) ? 1 : 0, Size - input.bignumSize, (uint8_t *)input.coord2, input.tls_id, ECDF_BYTECEIL(input.groupBitLen)) != 0) {
      // point not on curve
      return 0;
    }
    input.coord2x = input.coord2 + 1;
    input.coord2y = input.coord2 + 1 + input.coordSize;
  } else {
    // mulitplying a point by a scalar
  }
  if (decompressPoint(input.bignum + input.bignumSize, (Data[2 + input.bignumSize] & 0x1) ? 1 : 0, Size - input.bignumSize, (uint8_t *)input.coord, input.tls_id, ECDF_BYTECEIL(input.groupBitLen)) != 0) {
    // point not on curve
    return 0;
  }
  input.coordx = input.coord + 1;
  input.coordy = input.coord + 1 + input.coordSize;
#ifdef DEBUG
  printf("curve=%d %s\n", input.tls_id, nameOfCurve(input.tls_id));
  printf("point=");
  for (i = 0; i < 2 * input.coordSize + 1; i++) {
    printf("%02x", input.coord[i]);
  }
  printf("\n");
  if (Data[2 + input.bignumSize] & 0x80) {
    printf("point2=");
    for (i = 0; i < 2 * input.coordSize + 1; i++) {
      printf("%02x", input.coord2[i]);
    }
  } else {
    printf("bignum=");
    for (i = 0; i < input.bignumSize; i++) {
      printf("%02x", input.bignum[i]);
    }
  }
  printf("\n");
#endif

  // iterate modules
  lastok = NBMODULES;
  for (i = 0; i < NBMODULES; i++) {
    if (Data[2 + input.bignumSize] & 0x80) {
      if (modules[i].add2p == NULL) {
        continue;
      }
      modules[i].add2p(&input, &output[i]);
    } else {
      modules[i].process(&input, &output[i]);
    }
#ifdef DEBUG
    printf("%s: %x ", modules[i].name, output[i].errorCode);
    if (output[i].errorCode == FUZZEC_ERROR_NONE) {
      for (size_t n = 0; n < output[i].pointSizes[0]; n++) {
        printf("%02x", output[i].points[0][n]);
      }
    }
    printf("\n");
#endif
    if (output[i].errorCode == FUZZEC_ERROR_NONE) {
      if (lastok == NBMODULES) {
        lastok = i;
        continue;
      }
      int failed = 0;
      for (k = 0; k < FUZZEC_NBPOINTS; k++) {
        if (output[i].pointSizes[k] == 0 || output[lastok].pointSizes[k] == 0) {
          continue;
        }
        if (output[i].pointSizes[k] != output[lastok].pointSizes[k]) {
          printf("Module %s and %s returned different lengths for test %zu : %zu vs %zu\n", modules[i].name, modules[lastok].name, k, output[i].pointSizes[k], output[lastok].pointSizes[k]);
          failTest(input.tls_id, i);
        }
        if (memcmp(output[i].points[k], output[lastok].points[k], output[i].pointSizes[k]) != 0) {
          printf("Module %s and %s returned different points for test %zu size %d\n", modules[i].name, modules[lastok].name, k, output[i].pointSizes[k]);
          failTest(input.tls_id, i);
          failed = 1;
        }
      }
      if (failed) {
        break;
      }
      lastok = i;
    } else if (output[i].errorCode != FUZZEC_ERROR_UNSUPPORTED) {
      printf("Module %s returned %d\n", modules[i].name, output[i].errorCode);
      abort();
    }
  }

  return 0;
}
