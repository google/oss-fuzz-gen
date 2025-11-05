# Stream Processor (Incremental Processing)

## Pattern
```c
while (has_data) {
  process_chunk(data, chunk_size);
}
```

Process data in chunks, not all at once.

---

## OSS-Fuzz Notes

### ⚠️ Must Limit Iterations

**❌ Wrong**:
```c
while (has_more_data()) {  // Infinite loop on malicious input
  process_next();
}
```

**✅ Right**:
```c
int max_iter = 1000;
while (has_more_data() && max_iter-- > 0) {
  process_next();
}
```

### ⚠️ Chunk Size from Fuzzer Data

```c
if (size < 2) return 0;
size_t chunk_size = data[0];  // First byte = chunk size
if (chunk_size == 0 || chunk_size > 1024) chunk_size = 256;

size_t offset = 1;
while (offset < size && max_iter-- > 0) {
  size_t len = min(chunk_size, size - offset);
  process_chunk(data + offset, len);
  offset += len;
}
```

---

## Real Examples

- **zlib**: `inflateInit()` → `inflate()` (loop) → `inflateEnd()`
- **bzip2**: `BZ2_bzDecompressInit()` → `BZ2_bzDecompress()` (loop) → `BZ2_bzDecompressEnd()`
- **libxml2 push parser**: `xmlParseChunk()` called repeatedly
