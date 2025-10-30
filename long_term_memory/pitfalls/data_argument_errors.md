# Data & Argument Errors

## Category
Missing validation or incorrect handling of data and arguments

## Impact
- Segmentation fault (NULL dereference)
- Buffer overflow
- False-positive crashes

## Common Patterns

### 1. Unchecked NULL Pointers

**Error**:
```c
Geometry *g = createGeometry(data, size);
// Missing NULL check
int area = getArea(g);  // Crash if g is NULL
```

**Fix**:
```c
Geometry *g = createGeometry(data, size);
if (!g) return 0;  // Postcondition check
int area = getArea(g);  // Now safe
```

**Detection**: Functions returning pointers

**Specification Mark**:
```yaml
postcondition:
  function: createGeometry
  returns: Geometry*
  success: non-NULL pointer
  failure: NULL
  check: "if (!g) return 0;"
  violation_risk: "Segfault in subsequent dereference"
```

---

### 2. Missing Bounds Validation

**Error**:
```c
// data[0] used as index without validation
int mode = data[0];
result = process_with_mode(mode, data + 1, size - 1);  // mode might be invalid
```

**Fix**:
```c
if (size < 1) return 0;
int mode = data[0] % MAX_MODES;  // Constrain to valid range
result = process_with_mode(mode, data + 1, size - 1);
```

**Detection**: Parameters used as indices or enum values

**Specification Mark**:
```yaml
parameter_strategy:
  mode:
    type: int
    construction: "data[0] % MAX_MODES"
    strategy: CONSTRAIN
    constraint: "0 <= mode < MAX_MODES"
    reason: "Invalid mode causes assertion"
```

---

### 3. Buffer Size Mismatches

**Error**:
```c
createCollection(type, geometries, 6);  // Hardcoded size
// But geometries array might have fewer elements
```

**Fix**:
```c
size_t actual_count = min(6, available_count);
createCollection(type, geometries, actual_count);
```

**Detection**: Size parameter doesn't match actual buffer size

**Specification Mark**:
```yaml
precondition:
  condition: "count <= actual_array_size"
  reason: "API accesses array[0..count-1]"
  violation: "Buffer overflow"
  enforcement: "size_t count = min(CONST, size / sizeof(elem));"
```

---

### 4. Modifying const Input

**Error**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  data[0] = 0;  // Undefined behavior: modifying const
  api_function(data, size);
}
```

**Fix**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *copy = malloc(size);
  if (!copy) return 0;
  memcpy(copy, data, size);
  
  copy[0] = 0;  // OK: modifying our copy
  api_function(copy, size);
  
  free(copy);
}
```

**Detection**: API modifies its input parameter

**Specification Mark**:
```yaml
parameter_strategy:
  data:
    needs_copy: true
    reason: "API modifies input buffer"
    code: |
      uint8_t *data_copy = malloc(size);
      memcpy(data_copy, data, size);
```

---

### 5. Uninitialized Struct Members

**Error**:
```c
struct Config cfg;
cfg.mode = data[0];
// cfg.buffer not initialized
api_configure(&cfg);  // Crash: reads uninitialized buffer
```

**Fix**:
```c
struct Config cfg = {0};  // Zero-initialize
cfg.mode = data[0];
cfg.buffer = allocated_buffer;
api_configure(&cfg);
```

**Detection**: Struct passed to API

**Specification Mark**:
```yaml
parameter_strategy:
  config:
    type: "struct Config"
    construction: |
      struct Config cfg = {0};
      cfg.mode = data[0];
      cfg.buffer = buffer;
    required_fields:
      - mode
      - buffer
```

---

### 6. Negative Size/Count

**Error**:
```c
int size = (int)data[0];  // Could be interpreted as negative
allocate(size);           // Huge allocation or crash
```

**Fix**:
```c
size_t size = data[0];  // Unsigned
if (size > MAX_SIZE) size = MAX_SIZE;
allocate(size);
```

**Detection**: Signed integer used for size

**Specification Mark**:
```yaml
parameter_strategy:
  count:
    type: size_t
    construction: "min(data[0], MAX_COUNT)"
    constraint: "0 <= count <= MAX_COUNT"
```

---

## Real Examples

### libGEOS: Missing NULL Check
```c
// WRONG
Geometry *g = createPoint(x, y);
double area = getArea(g);  // Crash if createPoint failed

// RIGHT
Geometry *g = createPoint(x, y);
if (!g) return 0;
double area = getArea(g);  // Safe
```

### libUCL: Buffer Size Mismatch
```c
// WRONG
ucl_parser_add_chunk(parser, data, wrong_size);  // Overflow

// RIGHT
size_t safe_size = min(size, MAX_CHUNK);
ucl_parser_add_chunk(parser, data, safe_size);
```

### HDF5: Invalid File ID
```c
// WRONG
hid_t file = H5Fopen(filename, flags, plist);
H5Dread(file, ...);  // Crash if H5Fopen failed

// RIGHT
hid_t file = H5Fopen(filename, flags, plist);
if (file < 0) return 0;  // Check error
H5Dread(file, ...);
```

---

## Prevention Checklist

-  Check ALL pointer returns for NULL
-  Validate array indices and sizes
-  Ensure buffer sizes match actual data
-  Don't modify const input
-  Initialize all struct members
-  Use unsigned types for sizes
-  Constrain enum/index values to valid range

---

## Specification Template

```yaml
postconditions:
  - function: api_create
    returns: ptr
    check: "if (!ptr) return 0;"
    
  - function: api_process
    returns: int
    check: "if (ret < 0) return 0;"

parameter_strategies:
  buffer:
    strategy: DIRECT_FUZZ
    
  size:
    strategy: CONSTRAIN
    constraint: "min(actual_size, MAX_SIZE)"
    
  index:
    strategy: CONSTRAIN
    constraint: "value % ARRAY_SIZE"
```

