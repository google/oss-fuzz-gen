# Data & Argument Errors in OSS-Fuzz

## OSS-Fuzz Specific Issues

### 1. Modifying const Input (Undefined Behavior)

**Problem**: `LLVMFuzzerTestOneInput` receives `const uint8_t *data` - modifying it is UB

**❌ Wrong**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  data[0] = 0;  // ❌ Undefined behavior: modifying const
  api_function(data, size);
}
```

**✅ Right**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *copy = malloc(size);
  if (!copy) return 0;
  memcpy(copy, data, size);
  
  copy[0] = 0;  // ✅ OK: modifying our copy
  api_function(copy, size);
  free(copy);
}
```

---

### 2. Constraining Fuzzer Data to Valid Range

When fuzzer data represents enum/index/mode:

**❌ Wrong**:
```c
int mode = data[0];  // Could be 255, but only 0-3 valid
result = process_mode(mode);  // Crash on invalid mode
```

**✅ Right**:
```c
if (size < 1) return 0;
int mode = data[0] % MAX_MODES;  // Constrain: 0 <= mode < MAX_MODES
result = process_mode(mode);
```

---

### 3. Struct Initialization

**❌ Wrong**:
```c
struct Config cfg;
cfg.mode = data[0];
// cfg.buffer uninitialized - contains garbage
api_configure(&cfg);  // Crash
```

**✅ Right**:
```c
struct Config cfg = {0};  // Zero-initialize all fields
cfg.mode = data[0];
cfg.buffer = buffer;
api_configure(&cfg);
```

---

## Real OSS-Fuzz Examples

### libGEOS: Constraining mode parameter
```c
// ❌ Wrong - mode can be any value
int mode = data[0];
GEOSGeom_normalize_r(ctx, geom, mode);  // Crash on invalid mode

// ✅ Right - constrain to valid range
int mode = data[0] % 3;  // Only 0, 1, 2 are valid
GEOSGeom_normalize_r(ctx, geom, mode);
```

### libUCL: Struct must be zero-initialized
```c
// ❌ Wrong
struct ucl_parser cfg;
cfg.flags = UCL_PARSER_KEY_LOWERCASE;
ucl_parser_add_chunk(parser, &cfg);  // Crash: other fields garbage

// ✅ Right
struct ucl_parser cfg = {0};  // Zero-init
cfg.flags = UCL_PARSER_KEY_LOWERCASE;
ucl_parser_add_chunk(parser, &cfg);
```

### HDF5: Modifying const input requires copy
```c
// ❌ Wrong
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  data[0] = 1;  // UB: modifying const
  H5LTmake_dataset(file, "data", 1, dims, H5T_NATIVE_INT, data);
}

// ✅ Right
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *copy = malloc(size);
  memcpy(copy, data, size);
  copy[0] = 1;  // OK
  H5LTmake_dataset(file, "data", 1, dims, H5T_NATIVE_INT, copy);
  free(copy);
}
```

---

## Quick Checklist

- [ ] Don't modify `const uint8_t *data` from fuzzer
- [ ] Constrain data to valid range: `data[0] % MAX_VALUE`
- [ ] Zero-initialize structs: `struct X cfg = {0};`
- [ ] Check `size` before accessing `data[i]`

