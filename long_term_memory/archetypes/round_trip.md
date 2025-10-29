# Round-trip Validator Archetype

## Pattern Signature
```
encode(data) → decode(encoded) → verify(data == decoded)
```

## Characteristics
- Symmetric operations (encode/decode, compress/decompress)
- Validation through round-trip
- Stronger testing than one-way
- Catches asymmetry bugs

## Typical APIs
- Compression libraries (zlib, brotli, lz4)
- Encryption libraries (with deterministic IV)
- Serialization formats (protobuf, msgpack)
- Format converters

## Preconditions
1. Original data valid
2. Encode succeeds
3. Encoded data complete
4. Decode with same parameters

## Postconditions
1. Encode returns compressed size
2. Decode returns original size
3. Round-trip preserves data
4. Errors reported on failure

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 100 * 1024) return 0;
  
  // Allocate buffers
  size_t compressed_size = compress_bound(size);
  uint8_t *compressed = malloc(compressed_size);
  if (!compressed) return 0;
  
  uint8_t *decompressed = malloc(size);
  if (!decompressed) {
    free(compressed);
    return 0;
  }
  
  // Encode
  int ret = compress(compressed, &compressed_size, data, size);
  if (ret != OK) goto cleanup;
  
  // Decode
  size_t decompressed_size = size;
  ret = uncompress(decompressed, &decompressed_size, 
                   compressed, compressed_size);
  if (ret != OK) goto cleanup;
  
  // Verify round-trip
  assert(decompressed_size == size);
  assert(memcmp(data, decompressed, size) == 0);
  
cleanup:
  free(decompressed);
  free(compressed);
  return 0;
}
```

## Parameter Strategy
- Original data: DIRECT_FUZZ
- Compression level: FIX (default or from first byte)
- Buffer sizes: CONSTRAIN (bound by input)
- Options: FIX (deterministic settings)

## Determinism Requirements

**For encryption**: Must use deterministic IV/nonce
```c
// WRONG: random nonce
randombytes_buf(nonce, sizeof(nonce));

// RIGHT: deterministic from input
memcpy(nonce, data, min(sizeof(nonce), size));
```

**For compression**: Use default settings
```c
// Consistent settings
compress_level = Z_DEFAULT_COMPRESSION;
```

## Common Pitfalls
- Non-deterministic encryption (random IV)
- Buffer too small for compressed data
- Not checking round-trip equality
- Memory leak on error path
- Using different parameters for encode/decode

## Assertion Strategy
```c
// Weak: only check no crash
compress(data); decompress(compressed);

// Strong: verify round-trip
assert(decompress(compress(data)) == data);
```

## Real Examples
- zlib: `compress()` → `uncompress()` → verify
- brotli: `BrotliEncode()` → `BrotliDecode()` → verify
- libsodium: `crypto_secretbox()` → `crypto_secretbox_open()` (with fixed nonce)
- JSON: `json_dumps()` → `json_loads()` → verify

## Buffer Size Calculation
```c
// Encode buffer: use API bound function
size_t enc_size = compress_bound(size);

// Decode buffer: original size
size_t dec_size = size;

// Check bounds
if (enc_size > MAX_BUFFER) return 0;
```

## Reference
See FUZZER_COOKBOOK.md Scenario 4, 5

