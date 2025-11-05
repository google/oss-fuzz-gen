# Round-trip (Encode → Decode Validation)

## Pattern
```c
encoded = encode(data);
decoded = decode(encoded);
// Optionally: verify(decoded == data)
```

Test symmetric operations.

---

## OSS-Fuzz Notes

### When to Use

When library has **both** encode and decode:
- Compression: `compress()` → `decompress()`
- Serialization: `serialize()` → `deserialize()`
- Encoding: `base64_encode()` → `base64_decode()`

### ⚠️ Don't Verify Equality (Usually)

**Most fuzzers DON'T verify roundtrip** - just test both code paths:

```c
// ✅ Simple approach - just exercise both paths
uint8_t *compressed = compress(data, size, &comp_size);
if (compressed) {
  decompress(compressed, comp_size, &orig_size);
  free(compressed);
}
```

**Only verify if finding logic bugs** (not memory safety):
```c
// Advanced: verify roundtrip correctness
uint8_t *compressed = compress(data, size, &comp_size);
if (compressed) {
  uint8_t *decompressed = decompress(compressed, comp_size, &orig_size);
  if (decompressed && orig_size == size) {
    assert(memcmp(data, decompressed, size) == 0);  // Logic bug if fails
    free(decompressed);
  }
  free(compressed);
}
```

---

## Real Examples

- **zlib**: `compress()` → `uncompress()`
- **protobuf**: `encode()` → `decode()`
- **msgpack**: `pack()` → `unpack()`
