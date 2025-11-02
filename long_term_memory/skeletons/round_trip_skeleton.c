// Round-trip Validator Pattern: encode → decode → verify

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > MAX_INPUT_SIZE) return 0;
  
  // Allocate buffers
  size_t encoded_size = ENCODE_BOUND(size);
  uint8_t *encoded = malloc(encoded_size);
  if (!encoded) return 0;
  
  uint8_t *decoded = malloc(size);
  if (!decoded) {
    free(encoded);
    return 0;
  }
  
  // Step 1: Encode
  int ret = ENCODE(encoded, &encoded_size, data, size);
  if (ret != OK) goto cleanup;
  
  // Step 2: Decode
  size_t decoded_size = size;
  ret = DECODE(decoded, &decoded_size, encoded, encoded_size);
  if (ret != OK) goto cleanup;
  
  // Step 3: Verify round-trip
  assert(decoded_size == size);
  assert(memcmp(data, decoded, size) == 0);
  
cleanup:
  free(decoded);
  free(encoded);
  return 0;
}
