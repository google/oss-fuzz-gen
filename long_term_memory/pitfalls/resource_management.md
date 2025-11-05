# Resource Management in OSS-Fuzz Harnesses

## Critical Pattern: Goto Cleanup

### ⚠️ Most Common Error: Missing Cleanup on Early Return

**Pattern (C)**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  uint8_t *buffer = malloc(SIZE);
  
  if (condition) goto cleanup;  // ✅ Correct
  // NOT: if (condition) return 0;  // ❌ Leaks obj and buffer
  
  obj_process(obj, buffer);

cleanup:
  if (buffer) free(buffer);
  if (obj) obj_destroy(obj);
  return 0;
}
```

**Cleanup Order**: Reverse of creation (LIFO)

---

## 🔴 C++ Specific: Goto Cannot Jump Over Variable Initialization

**Problem**: C++ forbids `goto` that jumps over variable declarations

**Compiler Error**:
```
error: cannot jump from this goto statement to its label
note: jump bypasses variable initialization
```

**❌ Wrong (causes compile error)**:
```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) return 0;
  
  igraph_t graph;
  igraph_vector_t vec;  // ← Variable declared here
  
  if (error) {
    goto cleanup;  // ❌ ERROR: jumps over 'vec' initialization below
  }
  
  igraph_vector_init(&vec, 10);  // ← Initialization here
  
cleanup:
  igraph_vector_destroy(&vec);  // May be uninitialized!
  return 0;
}
```

**✅ Solution: Declare ALL variables at function start**:
```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Declare ALL variables BEFORE any goto
  igraph_t graph;
  igraph_vector_t vec;
  bool vec_init = false;
  bool graph_init = false;
  
  if (size < 10) return 0;
  
  if (igraph_vector_init(&vec, 10) != SUCCESS) goto cleanup;
  vec_init = true;
  
  if (igraph_create(&graph, &vec) != SUCCESS) goto cleanup;
  graph_init = true;
  
  // ... use graph and vec ...

cleanup:
  if (graph_init) igraph_destroy(&graph);
  if (vec_init) igraph_vector_destroy(&vec);
  return 0;
}
```

**Key Rule**: In C++, declare all variables **at the top** before any `goto` statement.

**Alternative (C++ RAII)**:
```cpp
struct AutoCleanup {
  igraph_vector_t vec;
  bool init = false;
  AutoCleanup() { init = (igraph_vector_init(&vec, 10) == SUCCESS); }
  ~AutoCleanup() { if (init) igraph_vector_destroy(&vec); }
};
```

---

## Other OSS-Fuzz Specific Pitfalls

### Stack Overflow
- ❌ `uint8_t buffer[10MB]` on stack
- ✅ Use `static uint8_t buffer[256KB]` or `malloc()`

### Unbounded Loops
- ❌ `while (has_more())` with fuzzer data
- ✅ `int max_iter = 1000; while (has_more() && max_iter-- > 0)`

### Temp Files
- ❌ Missing `unlink(filename)` after `api_load_file()`
- ✅ Always cleanup: `api_load_file(f); unlink(f);`

---

## Real OSS-Fuzz Examples

### libarchive: Missing cleanup on error
```c
// ❌ Wrong
archive_t *a = archive_read_new();
if (archive_read_open(a, ...) != OK) {
  return 0;  // Leak
}

// ✅ Right
if (archive_read_open(a, ...) != OK) {
  archive_read_free(a);  // Must free on error
  return 0;
}
```

### SQLite: Unbounded loop causes timeout
```c
// ❌ Wrong
while (sqlite3_step(stmt) == SQLITE_ROW) {
  // Infinite loop with malicious DB
}

// ✅ Right
int max_rows = 10000;
while (sqlite3_step(stmt) == SQLITE_ROW && max_rows-- > 0) {
  // Protected
}
```

### zlib: Stack overflow
```c
// ❌ Wrong
uint8_t buffer[10 * 1024 * 1024];  // Too large for stack

// ✅ Right
static uint8_t buffer[256 * 1024];  // Static, reused across calls
```

---

## Quick Checklist

- [ ] Use `goto cleanup` in C (not early `return`)
- [ ] In C++: declare all variables at function start before goto
- [ ] Cleanup in reverse order (LIFO)
- [ ] Limit loop iterations with counter
- [ ] Use `static` or `malloc()` for large buffers (>1MB)
- [ ] Always `unlink()` temp files

