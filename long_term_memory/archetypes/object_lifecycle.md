# Object Lifecycle Archetype

## Pattern Signature
```
create() → use(obj, data) → destroy(obj)
```

## Characteristics
- Explicit creation and destruction
- Object handle passed between calls
- Clear resource ownership (caller owns)
- State maintained in object

## Typical APIs
- Parser objects (libxml2, libyaml)
- Codec instances (image/video decoders)
- Database connections
- File format handlers

## Preconditions
1. Object must be created before use
2. Object handle must be non-NULL
3. Object must not be already destroyed
4. Required initialization completed

## Postconditions
1. create() returns NULL on failure
2. use() returns error if object invalid
3. destroy() invalidates object
4. destroy() safe on NULL (for some APIs)

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;
  
  // Create
  obj_t *obj = obj_create();
  if (!obj) return 0;  // Postcondition check
  
  // Use
  int ret = obj_process(obj, data, size);
  if (ret < 0) goto cleanup;
  
  // Optional: more operations
  obj_query(obj);
  
  // Destroy
cleanup:
  obj_destroy(obj);
  return 0;
}
```

## Parameter Strategy
- Object handle: FIX (from create(), not fuzzed)
- Data buffer: DIRECT_FUZZ
- Size: DIRECT_FUZZ
- Options: CONSTRAIN (extract from data)

## Common Pitfalls
- Not checking create() return (NULL dereference)
- Using object after destroy (use-after-free)
- Not destroying on error path (memory leak)
- Double-free (destroying twice)

## Cleanup Pattern
```c
cleanup:
  if (obj) obj_destroy(obj);  // NULL-safe variant
  return 0;
```

Or strict order:
```c
cleanup:
  obj_destroy(obj);  // Must be non-NULL
  return 0;
```

## Real Examples
- libGEOS: `GEOS_init_r()` → `GEOSGeomFromWKT()` → `GEOSGeom_destroy()`
- HDF5: `H5Fopen()` → `H5Dread()` → `H5Fclose()`
- libyaml: `yaml_parser_initialize()` → `yaml_parser_parse()` → `yaml_parser_delete()`
- mbedTLS: `mbedtls_x509_crt_init()` → `mbedtls_x509_crt_parse()` → `mbedtls_x509_crt_free()`

## State Transitions
```
NULL → create() → INITIALIZED → use() → ACTIVE → destroy() → FREED
```

Invalid transitions:
- `use()` on NULL → crash
- `use()` after `destroy()` → use-after-free
- `destroy()` twice → double-free

## Reference
See FUZZER_COOKBOOK.md Scenario 2, 3

