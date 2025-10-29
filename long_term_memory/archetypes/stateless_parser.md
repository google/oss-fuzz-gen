# Stateless Parser Archetype

## Pattern Signature
```
parse(data, size) → result
```

## Characteristics
- Single function call, no state maintained
- No initialization or cleanup needed
- Each invocation is independent
- Pure function behavior (same input → same output)

## Typical APIs
- JSON/XML/YAML parsers
- Image decoders (from memory buffer)
- Text format parsers
- Checksum/hash functions

## Preconditions
1. Input buffer valid (or NULL with size 0)
2. Size parameter accurate

## Postconditions
1. Returns result or error code
2. No side effects on global state
3. Output independent of previous calls

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE || size > MAX_SIZE) return 0;
  
  // Direct call, no setup
  result = parse_function(data, size);
  
  // Optional: verify result
  if (result != NULL) {
    // Use result
    free_result(result);
  }
  
  return 0;
}
```

## Parameter Strategy
- Input buffer: DIRECT_FUZZ (use fuzzer data directly)
- Size parameter: DIRECT_FUZZ (use fuzzer size)
- Options/flags: CONSTRAIN (extract from first bytes)

## Common Pitfalls
- Assuming minimum input size without checking
- Not handling size=0 case
- Modifying const input buffer

## Real Examples
- `json_parse(data, size)` - cJSON
- `yaml_parser_parse()` - libyaml
- `wasm_decode()` - wabt
- `png_decode()` - libpng (memory variant)

## Reference
See FUZZER_COOKBOOK.md Scenario 1

