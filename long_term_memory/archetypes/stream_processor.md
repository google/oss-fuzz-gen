# Stream Processor Archetype

## Pattern Signature
```
init() → while(has_data) { process_chunk() } → finalize()
```

## Characteristics
- Incremental data processing
- Loop-based consumption
- Maintains state between chunks
- Explicit finalization

## Typical APIs
- Archive readers (ZIP/TAR)
- Streaming decoders (brotli, lz4)
- SAX-style parsers
- Network protocol handlers

## Preconditions
1. Stream initialized
2. Chunks processed in order
3. Loop termination guaranteed
4. Finalization after all chunks

## Postconditions
1. process_chunk() returns status
2. State updated after each chunk
3. EOF/error stops loop
4. finalize() completes processing

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;
  
  // Initialize
  archive_t *archive = archive_read_new();
  if (!archive) return 0;
  
  archive_read_support_format_all(archive);
  
  if (archive_read_open_memory(archive, data, size) != OK) {
    archive_read_free(archive);
    return 0;
  }
  
  // Process stream
  entry_t *entry;
  int max_entries = 100;  // CRITICAL: prevent infinite loop
  
  while (max_entries-- > 0) {
    int ret = archive_read_next_header(archive, &entry);
    if (ret == EOF) break;
    if (ret != OK) break;
    
    // Read entry data in chunks
    uint8_t buffer[4096];
    ssize_t n;
    int max_reads = 1000;  // CRITICAL: prevent infinite loop
    
    while ((n = archive_read_data(archive, buffer, sizeof(buffer))) > 0 
           && max_reads-- > 0) {
      // Process chunk
    }
    
    if (n < 0) break;  // Error
  }
  
  // Finalize
  archive_read_close(archive);
  archive_read_free(archive);
  return 0;
}
```

## Parameter Strategy
- Stream handle: FIX (from init)
- Chunk data: DIRECT_FUZZ (from stream)
- Chunk size: CONSTRAIN (limited buffer)
- Loop iterations: FIX (max limit)

## Loop Protection
**CRITICAL**: Always limit iterations

```c
// Outer loop: max entries
int max_entries = 100;
while (has_next() && max_entries-- > 0) {
  
  // Inner loop: max reads per entry
  int max_reads = 1000;
  while (read_chunk() > 0 && max_reads-- > 0) {
    // Process
  }
}
```

Without limits: timeout or OOM

## Common Pitfalls
- Unbounded loops (timeout)
- Not checking read errors (infinite loop)
- Not limiting chunk count (zip bomb)
- Memory accumulation in loop (OOM)
- Early break without cleanup

## Error Handling
```c
while (max_iter-- > 0) {
  ret = process_chunk();
  
  if (ret == EOF) break;      // Normal end
  if (ret == ERROR) break;    // Error, stop
  if (ret == RETRY) continue; // Transient, retry
  
  // Success, continue
}
```

## Real Examples
- libarchive: `archive_read_next_header()` in loop
- brotli: `BrotliDecoderDecompressStream()` incremental
- libxml2: SAX parser callbacks
- libpcap: `pcap_loop()` with packet handler

## Cleanup Pattern
```c
cleanup:
  // Safe even if partially processed
  stream_close(stream);
  stream_free(stream);
  return 0;
```

## Reference
See FUZZER_COOKBOOK.md Scenario 7

