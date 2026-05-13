// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_indefinite_bytestring at bytestrings.c:42:14 in bytestrings.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_bytestring_is_indefinite at bytestrings.c:27:6 in bytestrings.h
// cbor_bytestring_add_chunk at bytestrings.c:92:6 in bytestrings.h
// cbor_bytestring_chunks_handle at bytestrings.c:80:15 in bytestrings.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
  if (Size < 1) return 0;

  // Create an indefinite byte string
  cbor_item_t* indefinite_item = cbor_new_indefinite_bytestring();
  if (!indefinite_item) return 0; // Allocation failed

  // Create a definite byte string chunk
  cbor_item_t* definite_chunk = cbor_new_definite_bytestring();
  if (!definite_chunk) {
    cbor_decref(&indefinite_item);
    return 0; // Allocation failed
  }

  // Allocate memory for the chunk data
  cbor_mutable_data chunk_data = (cbor_mutable_data)malloc(Size);
  if (!chunk_data) {
    cbor_decref(&definite_chunk);
    cbor_decref(&indefinite_item);
    return 0; // Allocation failed
  }

  // Copy the input data to the chunk data
  memcpy(chunk_data, Data, Size);

  // Set data for the definite byte string
  cbor_bytestring_set_handle(definite_chunk, chunk_data, Size);

  // Check if the indefinite item is indeed indefinite
  assert(cbor_bytestring_is_indefinite(indefinite_item));

  // Add the chunk to the indefinite byte string
  bool success = cbor_bytestring_add_chunk(indefinite_item, definite_chunk);
  if (success) {
    // Retrieve chunks handle and verify
    cbor_item_t** chunks = cbor_bytestring_chunks_handle(indefinite_item);
    assert(chunks != nullptr);
  }

  // Cleanup
  cbor_decref(&definite_chunk);
  cbor_decref(&indefinite_item);

  return 0;
}